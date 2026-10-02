//! Explicit Unicode 15/16 default lowercase, including contextual final sigma.
use super::{Result, bad};

const VALUE_LIMIT: usize = 8192;

pub(crate) struct Lowercase {
    version15: bool,
    cased: Vec<(char, char)>,
    ignorable: Vec<(char, char)>,
}

impl Lowercase {
    pub(crate) fn compile(version: &str) -> Result<Self> {
        let version15 = match version {
            "15.0.0" if unicode_case_mapping15::UNICODE_VERSION == (15, 0, 0) => true,
            "16.0.0" if unicode_case_mapping::UNICODE_VERSION == (16, 0, 0) => false,
            _ => return Err(bad("invalid_wordpress_unicode_version")),
        };
        let property = if version15 { property15 } else { property16 };
        Ok(Self {
            version15,
            cased: property(r"\p{Cased}")?,
            ignorable: property(r"\p{Case_Ignorable}")?,
        })
    }

    pub(crate) fn apply(&self, input: &str) -> Result<String> {
        if input.len() > VALUE_LIMIT || input.contains('\0') {
            return Err(bad("wordpress_projection_value_limit"));
        }
        // Classify once and compute right context backwards. Repeated sigma
        // characters must not cause a quadratic scan of the remaining string.
        let characters: Vec<_> = input.chars().collect();
        let properties: Vec<_> = characters
            .iter()
            .map(|c| (contains(&self.cased, *c), contains(&self.ignorable, *c)))
            .collect();
        let mut following_cased = vec![false; characters.len()];
        let mut next = false;
        for index in (0..characters.len()).rev() {
            following_cased[index] = next;
            if !properties[index].1 {
                next = properties[index].0;
            }
        }
        let mut previous = false;
        let mut output = String::new();
        for (index, character) in characters.iter().copied().enumerate() {
            let mapping = if character == 'Σ' && previous && !following_cased[index] {
                ['ς' as u32, 0]
            } else {
                if self.version15 {
                    unicode_case_mapping15::to_lowercase(character)
                } else {
                    unicode_case_mapping::to_lowercase(character)
                }
            };
            if mapping[0] == 0 {
                push(&mut output, character)?;
            } else {
                for value in mapping.into_iter().filter(|v| *v != 0) {
                    let scalar = char::from_u32(value)
                        .ok_or_else(|| bad("invalid_wordpress_unicode_mapping"))?;
                    push(&mut output, scalar)?;
                }
            }
            if !properties[index].1 {
                previous = properties[index].0;
            }
        }
        Ok(output)
    }
}

// Parse only fixed property names from exactly pinned Unicode table versions.
// HIR normalization supplies sorted disjoint ranges; no arbitrary regex is accepted.
fn property15(name: &str) -> Result<Vec<(char, char)>> {
    use regex_syntax15::hir::{Class, HirKind};
    let hir = regex_syntax15::Parser::new()
        .parse(name)
        .map_err(|_| bad("invalid_wordpress_unicode_properties"))?;
    if let HirKind::Class(Class::Unicode(class)) = hir.kind() {
        let ranges: Vec<_> = class.iter().map(|r| (r.start(), r.end())).collect();
        if ranges.len() <= 2048 {
            return Ok(ranges);
        }
    }
    Err(bad("invalid_wordpress_unicode_properties"))
}
fn property16(name: &str) -> Result<Vec<(char, char)>> {
    use regex_syntax::hir::{Class, HirKind};
    let hir = regex_syntax::Parser::new()
        .parse(name)
        .map_err(|_| bad("invalid_wordpress_unicode_properties"))?;
    if let HirKind::Class(Class::Unicode(class)) = hir.kind() {
        let ranges: Vec<_> = class.iter().map(|r| (r.start(), r.end())).collect();
        if ranges.len() <= 2048 {
            return Ok(ranges);
        }
    }
    Err(bad("invalid_wordpress_unicode_properties"))
}
fn contains(ranges: &[(char, char)], scalar: char) -> bool {
    let index = ranges.partition_point(|(_, end)| *end < scalar);
    ranges.get(index).is_some_and(|(start, _)| *start <= scalar)
}

fn push(output: &mut String, scalar: char) -> Result<()> {
    if output.len() + scalar.len_utf8() > VALUE_LIMIT {
        return Err(bad("wordpress_projection_value_limit"));
    }
    output.push(scalar);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lowercase_is_default_casing_with_contextual_sigma_not_case_folding() {
        let table = Lowercase::compile("16.0.0").unwrap();
        for (input, expected) in [
            ("ASCII/İ/ẞ/ß/ﬀ", "ascii/i\u{307}/ß/ß/ﬀ"),
            ("Σ/ΟΣ/ΟΣΑ/ΟΣ./1Σ", "σ/ος/οσα/ος./1σ"),
            ("ΟΣ\u{301}", "ος\u{301}"),
            ("ΟΣ\u{301}Α", "οσ\u{301}α"),
            ("Ο\u{301}Σ", "ο\u{301}ς"),
            ("Ο'Σ'Α", "ο'σ'α"),
            ("Ο-Σ", "ο-σ"),
            ("\u{1c89}", "\u{1c8a}"),
            ("猫🦀", "猫🦀"),
        ] {
            assert_eq!(table.apply(input).unwrap(), expected);
        }
    }
    #[test]
    fn mapping_and_context_properties_use_the_same_declared_version() {
        let old = Lowercase::compile("15.0.0").unwrap();
        let new = Lowercase::compile("16.0.0").unwrap();
        assert_eq!(old.apply("\u{1c89}Σ/Ο'Σ").unwrap(), "\u{1c89}σ/ο'ς");
        assert_eq!(new.apply("\u{1c89}Σ/Ο'Σ").unwrap(), "\u{1c8a}ς/ο'ς");
        assert_eq!(old.apply("ΟΣ\u{a7cb}").unwrap(), "ος\u{a7cb}");
        assert_eq!(new.apply("ΟΣ\u{a7cb}").unwrap(), "οσɤ");
    }
    #[test]
    fn version_input_and_expansion_limits_fail_without_truncation() {
        for version in ["", "14.0.0", "15.1.0", "17.0.0"] {
            assert!(Lowercase::compile(version).is_err());
        }
        let table = Lowercase::compile("16.0.0").unwrap();
        assert!(table.apply("safe\0").is_err());
        assert!(table.apply(&"a".repeat(8193)).is_err());
        assert_eq!(table.apply(&"İ".repeat(2730)).unwrap().len(), 8190);
        assert!(table.apply(&"İ".repeat(2731)).is_err());
        assert_eq!(
            table.apply(&"Σ".repeat(4096)).unwrap(),
            format!("{}ς", "σ".repeat(4095))
        );
    }
    #[test]
    fn linear_context_pass_agrees_with_independent_neighbor_search() {
        let table = Lowercase::compile("16.0.0").unwrap();
        let alphabet = ['A', 'Σ', '\u{301}', '-', '1'];
        for length in 0..=6_u32 {
            for mut index in 0..alphabet.len().pow(length) {
                let mut characters = Vec::new();
                for _ in 0..length {
                    characters.push(alphabet[index % alphabet.len()]);
                    index /= alphabet.len();
                }
                let mut expected = String::new();
                for (i, c) in characters.iter().copied().enumerate() {
                    let cased = |c: &char| *c == 'A' || *c == 'Σ';
                    let before = characters[..i]
                        .iter()
                        .rev()
                        .find(|c| **c != '\u{301}')
                        .is_some_and(cased);
                    let after = characters[i + 1..]
                        .iter()
                        .find(|c| **c != '\u{301}')
                        .is_some_and(cased);
                    expected.push(match c {
                        'A' => 'a',
                        'Σ' if before && !after => 'ς',
                        'Σ' => 'σ',
                        other => other,
                    });
                }
                assert_eq!(
                    table.apply(&characters.iter().collect::<String>()).unwrap(),
                    expected
                );
            }
        }
    }
}
