//! Bounded literal projections with explicit one-pass or ordered semantics.
//! No application tables are built in.
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

/// Each configured pair is one global non-overlapping replacement pass.
/// Later pairs inspect the preceding pass output; a pair never rescans itself.
pub(crate) struct OrderedReplacement {
    mappings: Vec<(String, String)>,
}
impl OrderedReplacement {
    pub(crate) fn compile(mappings: &[Mapping]) -> Result<Self> {
        if mappings.is_empty()
            || mappings.len() > 128
            || mappings.iter().any(|m| {
                m.from.is_empty()
                    || m.from.len() > 16
                    || m.to.len() > 16
                    || m.from.contains('\0')
                    || m.to.contains('\0')
            })
        {
            return Err(bad("invalid_wordpress_ordered_replacement"));
        }
        // Order and duplicates are intentional; neither sorting nor deduplication
        // preserves the declared cascade semantics. At most 4096 table bytes.
        Ok(Self {
            mappings: mappings
                .iter()
                .map(|m| (m.from.clone(), m.to.clone()))
                .collect(),
        })
    }
    pub(crate) fn apply(&self, input: &str) -> Result<String> {
        if input.len() > 8192 || input.contains('\0') {
            return Err(bad("wordpress_projection_value_limit"));
        }
        let mut value = input.to_owned();
        for (from, to) in &self.mappings {
            let mut next = String::new();
            let mut end = 0;
            for (offset, matched) in value.match_indices(from.as_str()) {
                append_checked(&mut next, &value[end..offset])?;
                append_checked(&mut next, to)?;
                end = offset + matched.len();
            }
            append_checked(&mut next, &value[end..])?;
            value = next;
        }
        Ok(value)
    }
}
fn append_checked(output: &mut String, piece: &str) -> Result<()> {
    if output.len() + piece.len() > 8192 {
        return Err(bad("wordpress_projection_value_limit"));
    }
    output.push_str(piece);
    Ok(())
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
    fn ordered(pairs: &[(&str, &str)]) -> OrderedReplacement {
        OrderedReplacement::compile(
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
    fn ordered_passes_cascade_preserve_declared_order_and_do_not_rescan_one_pair() {
        assert_eq!(
            ordered(&[("XY", ""), ("AB", "")]).apply("AXYB").unwrap(),
            ""
        );
        assert_eq!(
            ordered(&[("AB", ""), ("XY", "")]).apply("AXYB").unwrap(),
            "AB"
        );
        assert_eq!(ordered(&[("a", "aa")]).apply("a").unwrap(), "aa");
        assert_eq!(
            ordered(&[("a", "aa"), ("a", "aa")]).apply("a").unwrap(),
            "aaaa"
        );
        assert_eq!(ordered(&[("aa", "X")]).apply("aaa").unwrap(), "Xa");
        assert_eq!(
            ordered(&[("猫", "é"), ("é", "x")]).apply("猫é😀").unwrap(),
            "xx😀"
        );
    }
    #[test]
    fn ordered_tables_and_every_intermediate_value_are_bounded() {
        for pairs in [
            vec![],
            vec![("", "x")],
            vec![("x\0", "")],
            vec![("x", "\0")],
            vec![("12345678901234567", "")],
            vec![("x", "12345678901234567")],
            vec![("a", ""); 129],
        ] {
            let mappings = pairs
                .into_iter()
                .map(|(from, to)| Mapping {
                    from: from.into(),
                    to: to.into(),
                })
                .collect::<Vec<_>>();
            assert!(OrderedReplacement::compile(&mappings).is_err());
        }
        assert_eq!(ordered(&[("a", ""); 128]).apply("abc").unwrap(), "bc");
        assert!(ordered(&[("a", "")]).apply(&"a".repeat(8193)).is_err());
        assert!(ordered(&[("a", "")]).apply("a\0").is_err());
        assert_eq!(
            ordered(&[("a", "aa")])
                .apply(&"a".repeat(4096))
                .unwrap()
                .len(),
            8192
        );
        // A later shrinking pass must not excuse an excessive intermediate value.
        assert!(
            ordered(&[("a", "aa"), ("aa", "")])
                .apply(&"a".repeat(4097))
                .is_err()
        );
    }
    #[test]
    fn ordered_passes_match_independent_standard_replacement_on_short_strings() {
        let alphabet = ["A", "B", "X", "Y", "猫"];
        let tables = [
            vec![("XY", ""), ("AB", "")],
            vec![("A", "BA"), ("B", "X")],
            vec![("猫", "Y"), ("Y", "")],
            vec![("A", "AA"), ("A", "B")],
        ];
        for width in 0..=5u32 {
            for mut code in 0..5usize.pow(width) {
                let mut value = String::new();
                for _ in 0..width {
                    value.push_str(alphabet[code % 5]);
                    code /= 5;
                }
                for table in &tables {
                    let expected = table
                        .iter()
                        .fold(value.clone(), |v, (from, to)| v.replace(from, to));
                    assert_eq!(ordered(table).apply(&value).unwrap(), expected);
                }
            }
        }
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
