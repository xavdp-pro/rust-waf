//! Bounded canonical bracket paths; application-specific coercion stays outside core.
#[derive(Debug, PartialEq, Eq)]
pub struct FormPath<'a> {
    segments: [&'a str; 8],
    len: usize,
}
impl<'a> FormPath<'a> {
    pub fn parse(name: &'a str) -> Option<Self> {
        if name.is_empty() || name.len() > 64 {
            return None;
        }
        let (path, rest) = Self::read_prefix(name)?;
        rest.is_empty().then_some(path)
    }
    pub(crate) fn canonical_prefix(name: &'a str) -> Option<Self> {
        Self::read_prefix(name).map(|(path, _)| path)
    }
    fn read_prefix(name: &'a str) -> Option<(Self, &'a str)> {
        let root_end = name.find('[').unwrap_or(name.len());
        let root = &name[..root_end];
        let valid = |s: &str| {
            !s.is_empty()
                && s.len() <= 64
                && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        };
        if !valid(root) {
            return None;
        }
        let mut path = Self {
            segments: [""; 8],
            len: 1,
        };
        path.segments[0] = root;
        let mut rest = &name[root_end..];
        while !rest.is_empty() {
            if path.len == 8 || !rest.starts_with('[') {
                break;
            }
            let Some(end) = rest.find(']') else {
                break;
            };
            let segment = &rest[1..end];
            if !valid(segment) {
                break;
            }
            path.segments[path.len] = segment;
            path.len += 1;
            rest = &rest[end + 1..];
        }
        Some((path, rest))
    }
    pub fn segments(&self) -> &[&'a str] {
        &self.segments[..self.len]
    }
    pub fn root(&self) -> &'a str {
        self.segments[0]
    }
    pub fn is_prefix_of(&self, other: &Self) -> bool {
        other.segments().starts_with(self.segments())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonical_paths_are_bounded_and_do_not_coerce_indices() {
        for valid in [
            "secret",
            "form[fields][1]",
            "form[fields][01]",
            "x[a][b][c][d][e][f][g]",
        ] {
            assert!(FormPath::parse(valid).is_some(), "{valid}");
        }
        for invalid in [
            "",
            "x[]",
            "x[a]tail",
            "x[a",
            "x.a[b]",
            "x[a b]",
            "x[a][b][c][d][e][f][g][h]",
            "x[a\0b]",
        ] {
            assert!(FormPath::parse(invalid).is_none(), "{invalid}");
        }
        assert!(FormPath::parse(&"a".repeat(65)).is_none());
        let one = FormPath::parse("form[fields][1]").unwrap();
        assert!(FormPath::parse("form[fields]").unwrap().is_prefix_of(&one));
        assert!(
            !FormPath::parse("form[fields][01]")
                .unwrap()
                .is_prefix_of(&one)
        );
    }
}
