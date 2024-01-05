#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![allow(clippy::len_without_is_empty)]
#![forbid(unsafe_code)]
#![warn(
    clippy::arithmetic_side_effects,
    clippy::mod_module_files,
    clippy::panic,
    clippy::panic_in_result_fn,
    clippy::unwrap_used,
    missing_docs,
    rust_2018_idioms,
    unused_lifetimes,
    unused_qualifications
)]

#[cfg(feature = "std")]
extern crate std;

#[macro_use]
mod checked;

mod arcs;
mod buffer;
mod encoder;
mod error;
mod parser;
mod traits;

#[cfg(feature = "db")]
pub mod db;

pub use crate::{
    arcs::{Arc, Arcs},
    buffer::Buffer,
    error::{Error, Result},
    traits::{AssociatedOid, DynAssociatedOid},
};

use crate::encoder::Encoder;
use core::{fmt, str::FromStr};

/// Default maximum size.
///
/// Makes `ObjectIdentifier` 40-bytes total w\ 1-byte length.
const DEFAULT_MAX_SIZE: usize = 39;

/// Object identifier (OID).
///
/// OIDs are hierarchical structures consisting of "arcs", i.e. integer
/// identifiers.
///
/// # Validity
///
/// In order for an OID to be considered valid by this library, it must meet
/// the following criteria:
///
/// - The OID MUST have at least 3 arcs
/// - The first arc MUST be within the range 0-2
/// - The second arc MUST be within the range 0-39
/// - The BER/DER encoding of the OID MUST be shorter than
///   [`ObjectIdentifier::MAX_SIZE`]
#[derive(Clone, Copy, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct ObjectIdentifier<const MAX_SIZE: usize = DEFAULT_MAX_SIZE> {
    /// Buffer containing BER/DER-serialized bytes (sans ASN.1 tag/length)
    buffer: Buffer<MAX_SIZE>,
}

impl ObjectIdentifier {
    /// Maximum size of a BER/DER-encoded OID in bytes.
    pub const MAX_SIZE: usize = DEFAULT_MAX_SIZE;

    /// Parse an [`ObjectIdentifier`] from the dot-delimited string form,
    /// panicking on parse errors.
    ///
    /// This function exists as a workaround for `unwrap` not yet being
    /// stable in `const fn` contexts, and is intended to allow the result to
    /// be bound to a constant value:
    ///
    /// ```
    /// use const_oid::ObjectIdentifier;
    ///
    /// pub const MY_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
    /// ```
    ///
    /// In future versions of Rust it should be possible to replace this with
    /// `ObjectIdentifier::new(...).unwrap()`.
    ///
    /// Use [`ObjectIdentifier::new`] for fallible parsing.
    // TODO(tarcieri): remove this when `Result::unwrap` is `const fn`
    pub const fn new_unwrap(s: &str) -> Self {
        match Self::new(s) {
            Ok(oid) => oid,
            Err(err) => err.panic(),
        }
    }

    /// Parse an [`ObjectIdentifier`] from the dot-delimited string form.
    pub const fn new(s: &str) -> Result<Self> {
        // TODO(tarcieri): use `?` when stable in `const fn`
        match parser::Parser::parse(s) {
            Ok(parser) => parser.finish(),
            Err(err) => Err(err),
        }
    }

    /// Parse an OID from a slice of [`Arc`] values (i.e. integers).
    pub fn from_arcs(arcs: impl IntoIterator<Item = Arc>) -> Result<Self> {
        let mut encoder = Encoder::new();

        for arc in arcs {
            encoder = encoder.arc(arc)?;
        }

        encoder.finish()
    }

    /// Parse an OID from from its BER/DER encoding.
    pub fn from_bytes(ber_bytes: &[u8]) -> Result<Self> {
        let len = ber_bytes.len();

        match len {
            0 => return Err(Error::Empty),
            3..=Self::MAX_SIZE => (),
            _ => return Err(Error::NotEnoughArcs),
        }

        let mut bytes = [0u8; Self::MAX_SIZE];
        bytes[..len].copy_from_slice(ber_bytes);

        let bytes = Buffer {
            bytes,
            length: len as u8,
        };

        let oid = Self { buffer: bytes };

        // Ensure arcs are well-formed
        let mut arcs = oid.arcs();
        while arcs.try_next()?.is_some() {}

        Ok(oid)
    }
}

impl<const MAX_SIZE: usize> ObjectIdentifier<MAX_SIZE> {
    /// Get the BER/DER serialization of this OID as bytes.
    ///
    /// Note that this encoding omits the tag/length, and only contains the value portion of the
    /// encoded OID.
    pub const fn as_bytes(&self) -> &[u8] {
        self.buffer.as_bytes()
    }

    /// Return the arc with the given index, if it exists.
    pub fn arc(&self, index: usize) -> Option<Arc> {
        self.arcs().nth(index)
    }

    /// Iterate over the arcs (a.k.a. nodes) of an [`ObjectIdentifier`].
    ///
    /// Returns [`Arcs`], an iterator over [`Arc`] values.
    pub fn arcs(&self) -> Arcs<'_> {
        Arcs::new(self.buffer.as_ref())
    }

    /// Get the length of this [`ObjectIdentifier`] in arcs.
    pub fn len(&self) -> usize {
        self.arcs().count()
    }

    /// Get the parent OID of this one (if applicable).
    pub fn parent(&self) -> Option<Self> {
        let num_arcs = self.len().checked_sub(1)?;
        let mut encoder = Encoder::new();

        for arc in self.arcs().take(num_arcs) {
            encoder = encoder.arc(arc).ok()?;
        }

        encoder.finish().ok()
    }

    /// Push an additional arc onto this OID, returning the child OID.
    pub const fn push_arc(self, arc: Arc) -> Result<Self> {
        // TODO(tarcieri): use `?` when stable in `const fn`
        match Encoder::extend(self).arc(arc) {
            Ok(encoder) => encoder.finish(),
            Err(err) => Err(err),
        }
    }

    /// Does this OID start with the other OID?
    pub const fn starts_with(&self, other: ObjectIdentifier) -> bool {
        let len = other.as_bytes().len();

        if self.as_bytes().len() < len {
            return false;
        }

        let mut i = 0;
        while i < len {
            if self.as_bytes()[i] != other.as_bytes()[i] {
                return false;
            }

            match i.checked_add(1) {
                Some(succ) => i = succ,
                None => return false,
            }
        }

        true
    }
}

impl<const MAX_SIZE: usize> AsRef<[u8]> for ObjectIdentifier<MAX_SIZE> {
    fn as_ref(&self) -> &[u8] {
        self.buffer.as_bytes()
    }
}

impl FromStr for ObjectIdentifier {
    type Err = Error;

    fn from_str(string: &str) -> Result<Self> {
        Self::new(string)
    }
}

impl TryFrom<&[u8]> for ObjectIdentifier {
    type Error = Error;

    fn try_from(ber_bytes: &[u8]) -> Result<Self> {
        Self::from_bytes(ber_bytes)
    }
}

impl<const MAX_SIZE: usize> fmt::Debug for ObjectIdentifier<MAX_SIZE> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ObjectIdentifier({})", self)
    }
}

impl<const MAX_SIZE: usize> fmt::Display for ObjectIdentifier<MAX_SIZE> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let len = self.arcs().count();

        for (i, arc) in self.arcs().enumerate() {
            write!(f, "{}", arc)?;

            if let Some(j) = i.checked_add(1) {
                if j < len {
                    write!(f, ".")?;
                }
            }
        }

        Ok(())
    }
}

// Implement by hand because the derive would create invalid values.
// Use the constructor to create a valid oid with at least 3 arcs.
#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for ObjectIdentifier {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let first = u.int_in_range(0..=arcs::ARC_MAX_FIRST)?;
        let second = u.int_in_range(0..=arcs::ARC_MAX_SECOND)?;
        let third = u.arbitrary()?;

        let mut oid = Self::from_arcs([first, second, third])
            .map_err(|_| arbitrary::Error::IncorrectFormat)?;

        for arc in u.arbitrary_iter()? {
            oid = oid
                .push_arc(arc?)
                .map_err(|_| arbitrary::Error::IncorrectFormat)?;
        }

        Ok(oid)
    }

    fn size_hint(depth: usize) -> (usize, Option<usize>) {
        (Arc::size_hint(depth).0.saturating_mul(3), None)
    }
}
