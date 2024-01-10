use std::collections::{BTreeMap, HashSet};

use regex::Regex;

#[derive(Clone, Debug)]
pub struct Asn1Parser {
    tree: BTreeMap<String, (Option<String>, Option<String>)>,
    base: BTreeMap<&'static str, &'static str>,
}

impl Asn1Parser {
    const DEF: &'static str = r"(?mx)
        (?P<name>[a-zA-Z][a-zA-Z0-9-]*)             # name
        \s+
        OBJECT
        \s+
        IDENTIFIER
        \s*
        ::=
        \s*
        \{
            \s*
            (?P<base>[a-zA-Z][a-zA-Z0-9-]*\s*)??    # base
            (?P<tail>                               # tail
                (?:
                    (?:
                        [a-zA-Z][a-zA-Z0-9-]*\([0-9]+\)\s*
                    )
                    |
                    (?:
                        [0-9]+\s*
                    )
                )*
            )
        \}
    ";

    const ARC: &'static str = r"(?mx)
        (?:
            [a-zA-Z][a-zA-Z0-9-]*\(([0-9]+)\)
        )
        |
        (?:
            ([0-9]+)
        )
    ";

    fn get_object_id_aliases(asn1: &str) -> HashSet<String> {
        // Using a Set because RFC's will often duplicate definitions.
        // The first definition in a descriptive section.
        // The second time in a complete ASN1 module appendix.
        let mut alias = HashSet::new();

        // In the input asn1, let's try to get "type aliases" for OBJECT IDENTIERs.
        //
        // For example in https://datatracker.ietf.org/doc/html/rfc5280#appendix-A.1,
        // The AttributeType is defined as below:
        //
        // AttributeType                   ::= OBJECT IDENTIFIER
        // id-at         OBJECT IDENTIFIER ::= { joint-iso-ccitt(2) ds(5) 4 }
        // id-at-name    AttributeType     ::= { id-at 41 }
        // ...
        // id-at-commonName  AttributeType ::= { id-at 3 }
        //
        // Get alias by finding "some_type ::= OBJECT IDENTIFIER"
        let re = Regex::new(r"(?P<alias>[a-zA-Z0-9-]*)\s+::=\s+OBJECT\s+IDENTIFIER\n").unwrap();
        for c in re.captures_iter(asn1) {
            alias.insert(c["alias"].to_string());
        }

        alias
    }

    fn replace_aliases(asn1: &str, aliases: &HashSet<String>) -> String {
        let mut replace_alias = asn1.to_string();

        for alias in aliases {
            let f = format!("(?P<ty>[a-z][a-zA-Z0-9-]+)[ ]+(?P<a>{alias})");
            let re = Regex::new(&f).unwrap();
            replace_alias = re.replace_all(&replace_alias, "$ty OBJECT IDENTIFIER").to_string();
        }

        replace_alias
    }
    pub fn new(asn1: &str, bases: &[(&'static str, &'static str)]) -> Self {

        let aliases = Self::get_object_id_aliases(asn1);
        let asn1 = &Self::replace_aliases(asn1, &aliases);

        let def = Regex::new(Self::DEF).unwrap();
        let arc = Regex::new(Self::ARC).unwrap();

        let mut base = BTreeMap::default();
        for (name, tail) in bases {
            base.insert(*name, *tail);
        }

        let mut tree = BTreeMap::default();
        for mat in def.find_iter(asn1) {
            let caps = def.captures(mat.as_str()).unwrap();
            let name = caps.name("name").unwrap().as_str().trim().to_string();
            let base = caps.name("base").map(|m| m.as_str().trim().to_string());
            let tail = caps.name("tail").map(|m| {
                arc.find_iter(m.as_str())
                    .map(|m| {
                        let c = arc.captures(m.as_str()).unwrap();
                        c.get(1).unwrap_or_else(|| c.get(2).unwrap()).as_str()
                    })
                    .collect::<Vec<_>>()
                    .join(".")
            });

            let tail = match tail.as_deref() {
                Some("") => None,
                _ => tail,
            };

            tree.insert(name, (base, tail));
        }

        Self { tree, base }
    }

    pub fn resolve(&self, name: &str) -> Option<String> {
        if let Some(tail) = self.base.get(name) {
            return Some(tail.to_string());
        }

        let (base, arcs) = self.tree.get(name)?;
        if let Some(base) = base {
            let base = self.resolve(base)?;
            if let Some(arcs) = arcs {
                Some(format!("{}.{}", base, arcs))
            } else {
                Some(base)
            }
        } else {
            arcs.clone()
        }
    }

    pub fn iter(&self) -> impl '_ + Iterator<Item = (String, String)> {
        self.tree
            .keys()
            .filter_map(|n| self.resolve(n).map(|p| (n.clone(), p)))
    }
}

#[test]
fn test() {
    let asn1 = super::Asn1Parser::new(
        r"
            foo OBJECT IDENTIFIER ::= { bar(1) baz(2) 3 }
            bat OBJECT IDENTIFIER ::= { foo qux(4) 5 }
            quz OBJECT IDENTIFIER ::= { bat 6 }
        ",
    );

    let answer = ("quz".to_string(), "1.2.3.4.5.6".to_string());

    let mut iter = asn1.iter();
    assert_eq!(Some(answer), iter.next());
    assert_eq!(None, iter.next());
}
