//! Bounded longest-key, one-pass literal translation. No application tables are built in.
use super::{Result, bad};
use serde::Deserialize;
use std::collections::BTreeSet;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Mapping {
    from: String,
    to: String,
}
#[derive(Default)]
struct Node {
    edges: Vec<(u8, usize)>,
    replacement: Option<String>,
}
pub(crate) struct Translation {
    nodes: Vec<Node>,
}
impl Translation {
    pub(crate) fn compile(mappings: &[Mapping]) -> Result<Self> {
        if mappings.is_empty() || mappings.len() > 512 {
            return Err(bad("invalid_wordpress_translation"));
        }
        let mut keys = BTreeSet::new();
        let mut key_bytes = 0;
        let mut total_bytes = 0;
        for mapping in mappings {
            key_bytes += mapping.from.len();
            total_bytes += mapping.from.len() + mapping.to.len();
            if mapping.from.is_empty()
                || mapping.from.len() > 16
                || mapping.to.len() > 16
                || mapping.from.contains('\0')
                || mapping.to.contains('\0')
                || !keys.insert(&mapping.from)
                || key_bytes > 4096
                || total_bytes > 8192
            {
                return Err(bad("invalid_wordpress_translation"));
            }
        }
        let mut translation = Self {
            nodes: vec![Node::default()],
        };
        for mapping in mappings {
            let mut node = 0;
            for byte in mapping.from.bytes() {
                node = match translation.nodes[node]
                    .edges
                    .binary_search_by_key(&byte, |e| e.0)
                {
                    Ok(index) => translation.nodes[node].edges[index].1,
                    Err(index) => {
                        let next = translation.nodes.len();
                        translation.nodes.push(Node::default());
                        translation.nodes[node].edges.insert(index, (byte, next));
                        next
                    }
                };
            }
            translation.nodes[node].replacement = Some(mapping.to.clone());
        }
        Ok(translation)
    }
    pub(crate) fn apply(&self, input: &str) -> Result<String> {
        if input.len() > 8192 || input.contains('\0') {
            return Err(bad("wordpress_projection_value_limit"));
        }
        let mut output = String::new();
        let mut offset = 0;
        while offset < input.len() {
            let mut node = 0;
            let mut selected = None;
            for (index, byte) in input.as_bytes()[offset..].iter().take(16).enumerate() {
                let Ok(edge) = self.nodes[node].edges.binary_search_by_key(byte, |e| e.0) else {
                    break;
                };
                node = self.nodes[node].edges[edge].1;
                if let Some(replacement) = &self.nodes[node].replacement {
                    selected = Some((index + 1, replacement.as_str()));
                }
            }
            let (consumed, replacement) = selected.unwrap_or_else(|| {
                let width = input[offset..].chars().next().unwrap().len_utf8();
                (width, &input[offset..offset + width])
            });
            if output.len() + replacement.len() > 8192 {
                return Err(bad("wordpress_projection_value_limit"));
            }
            output.push_str(replacement);
            offset += consumed;
        }
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn translation(pairs: &[(&str, &str)]) -> Translation {
        Translation::compile(
            &pairs
                .iter()
                .map(|(from, to)| Mapping {
                    from: (*from).into(),
                    to: (*to).into(),
                })
                .collect::<Vec<_>>(),
        )
        .unwrap()
    }
    #[test]
    fn longest_keys_win_without_recursive_or_order_dependent_translation() {
        for pairs in [
            vec![("a", "aa"), ("ab", "x"), ("x", "")],
            vec![("x", ""), ("ab", "x"), ("a", "aa")],
        ] {
            let table = translation(&pairs);
            assert_eq!(table.apply("abaax").unwrap(), "xaaaa");
            assert_eq!(table.apply("ab").unwrap(), "x");
        }
        assert_eq!(
            translation(&[("é", "e"), ("e\u{301}", "e"), ("l·l", "ll")])
                .apply("é/e\u{301}/l·l/猫")
                .unwrap(),
            "e/e/ll/猫"
        );
    }
    #[test]
    fn trie_agrees_with_independent_longest_prefix_reference() {
        let pairs = [("a", "b"), ("ab", "é"), ("b", "a"), ("é", ""), ("éa", "猫")];
        let table = translation(&pairs);
        for number in 0..4096 {
            let mut index = number;
            let mut input = String::new();
            for _ in 0..6 {
                input.push(['a', 'b', 'é', '猫'][index % 4]);
                index /= 4;
            }
            let mut remaining = input.as_str();
            let mut reference = String::new();
            while !remaining.is_empty() {
                if let Some((key, value)) = pairs
                    .iter()
                    .filter(|(key, _)| remaining.starts_with(key))
                    .max_by_key(|(key, _)| key.len())
                {
                    reference.push_str(value);
                    remaining = &remaining[key.len()..];
                } else {
                    let width = remaining.chars().next().unwrap().len_utf8();
                    reference.push_str(&remaining[..width]);
                    remaining = &remaining[width..];
                }
            }
            assert_eq!(table.apply(&input).unwrap(), reference, "{input}");
        }
    }
    #[test]
    fn configured_table_dimensions_are_checked_before_allocation() {
        let one = |from: String, to: String| Mapping { from, to };
        assert!(Translation::compile(&[one("a".repeat(17), "x".into())]).is_err());
        assert!(Translation::compile(&[one("a".into(), "x".repeat(17))]).is_err());
        let make = |n: usize, width: usize, replacement: usize| {
            (0..n)
                .map(|i| {
                    one(
                        format!("{i:04}{}", "k".repeat(width - 4)),
                        "x".repeat(replacement),
                    )
                })
                .collect::<Vec<_>>()
        };
        assert!(Translation::compile(&make(512, 8, 8)).is_ok());
        assert!(Translation::compile(&make(513, 4, 1)).is_err());
        assert!(Translation::compile(&make(512, 9, 0)).is_err());
        assert!(Translation::compile(&make(512, 8, 9)).is_err());
    }

    #[test]
    fn invalid_tables_fail_eagerly_and_expansion_never_truncates() {
        for pairs in [
            vec![],
            vec![("", "x")],
            vec![("a", "x"), ("a", "y")],
            vec![("a", "\0")],
            vec![("\0", "x")],
        ] {
            let table = pairs
                .into_iter()
                .map(|(from, to)| Mapping {
                    from: from.into(),
                    to: to.into(),
                })
                .collect::<Vec<_>>();
            assert!(Translation::compile(&table).is_err());
        }
        let table = translation(&[("a", "aa")]);
        assert_eq!(table.apply(&"a".repeat(4096)).unwrap().len(), 8192);
        assert!(table.apply(&"a".repeat(4097)).is_err());
        assert!(table.apply(&"b".repeat(8193)).is_err());
        assert!(table.apply("b\0").is_err());
        assert_eq!(
            translation(&[("é", "")]).apply(&"é".repeat(4096)).unwrap(),
            ""
        );
    }
}
