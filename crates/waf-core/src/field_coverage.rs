//! All-match field provenance with bounded earliest-start Thompson state tags.
use crate::{form_scan::FieldSpan, profile::PolicyError};
use regex_automata::{
    nfa::thompson::{NFA, State},
    util::primitives::StateID,
};
use std::collections::BTreeSet;

type Result<T> = std::result::Result<T, PolicyError>;

#[derive(Default)]
pub(crate) struct Coverage {
    pub fields: BTreeSet<String>,
    pub candidates: BTreeSet<String>,
    pub unscoped: bool,
}

struct States {
    starts: Vec<usize>,
    visited: Vec<StateID>,
    consuming: Vec<StateID>,
}
impl States {
    fn new(size: usize) -> Self {
        Self {
            starts: vec![usize::MAX; size],
            visited: Vec::new(),
            consuming: Vec::new(),
        }
    }
    fn clear(&mut self) {
        for id in self.visited.drain(..) {
            self.starts[id.as_usize()] = usize::MAX;
        }
        self.consuming.clear();
    }
    fn add(
        &mut self,
        nfa: &NFA,
        text: &[u8],
        at: usize,
        seed: StateID,
        start: usize,
        stack: &mut Vec<StateID>,
    ) -> Result<()> {
        stack.clear();
        stack.push(seed);
        while let Some(id) = stack.pop() {
            let previous = self.starts[id.as_usize()];
            if previous != usize::MAX {
                if previous > start {
                    return Err(PolicyError("field_coverage_order_violation".into()));
                }
                continue;
            }
            self.starts[id.as_usize()] = start;
            self.visited.push(id);
            match nfa.state(id) {
                State::Look { look, next } => {
                    if nfa.look_matcher().matches(*look, text, at) {
                        stack.push(*next);
                    }
                }
                State::Union { alternates } => stack.extend(alternates.iter().copied()),
                State::BinaryUnion { alt1, alt2 } => {
                    stack.push(*alt1);
                    stack.push(*alt2);
                }
                State::Capture { next, .. } => stack.push(*next),
                State::Fail => {}
                State::ByteRange { .. }
                | State::Sparse(_)
                | State::Dense(_)
                | State::Match { .. } => {
                    if self
                        .consuming
                        .last()
                        .is_some_and(|last| self.starts[last.as_usize()] > start)
                    {
                        return Err(PolicyError("field_coverage_order_violation".into()));
                    }
                    self.consuming.push(id);
                }
            }
        }
        Ok(())
    }
}

pub(crate) struct Cache {
    current: States,
    next: States,
    stack: Vec<StateID>,
}
impl Cache {
    pub fn new(nfa: &NFA) -> Self {
        let size = nfa.states().len();
        Self {
            current: States::new(size),
            next: States::new(size),
            stack: Vec::new(),
        }
    }
    pub fn scan(&mut self, nfa: &NFA, text: &str, spans: &[FieldSpan]) -> Result<Coverage> {
        self.current.clear();
        self.next.clear();
        let mut spans = spans.iter().collect::<Vec<_>>();
        spans.sort_by_key(|span| span.range.start);
        let bytes = text.as_bytes();
        let mut coverage = Coverage::default();
        for at in 0..=bytes.len() {
            // Earlier starters are propagated first; a new anchored start is last.
            // At the same state/position, all future transitions are identical.
            // Retaining the earliest start therefore covers every possible span:
            // if it fits one field at an accepting end, every later start does too.
            if text.is_char_boundary(at) {
                self.current
                    .add(nfa, bytes, at, nfa.start_anchored(), at, &mut self.stack)?;
            }
            for &id in &self.current.consuming {
                let start = self.current.starts[id.as_usize()];
                let next = match nfa.state(id) {
                    State::Match { .. } => {
                        if text.is_char_boundary(at) {
                            let index = spans.partition_point(|span| span.range.start <= start);
                            let field = index
                                .checked_sub(1)
                                .and_then(|i| spans.get(i))
                                .filter(|span| start < at && at <= span.range.end);
                            match field {
                                Some(span) => {
                                    if !coverage.fields.contains(&span.name) {
                                        coverage.fields.insert(span.name.clone());
                                    }
                                }
                                None => {
                                    coverage.unscoped = true;
                                    return Ok(coverage);
                                }
                            }
                        }
                        None
                    }
                    State::ByteRange { trans } => trans.matches(bytes, at).then_some(trans.next),
                    State::Sparse(trans) => trans.matches(bytes, at),
                    State::Dense(trans) => trans.matches(bytes, at),
                    _ => unreachable!("epsilon states are excluded from consuming states"),
                };
                if let Some(next) = next {
                    self.next
                        .add(nfa, bytes, at + 1, next, start, &mut self.stack)?;
                }
            }
            self.current.clear();
            std::mem::swap(&mut self.current, &mut self.next);
        }
        Ok(coverage)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use regex_automata::{Anchored, Input, MatchKind, nfa::thompson::pikevm::PikeVM};

    #[test]
    fn earliest_start_tags_agree_with_exhaustive_anchored_all_match_searches() {
        let mut texts = vec![String::new()];
        for _ in 0..3 {
            let previous = texts.clone();
            for text in previous {
                for suffix in ["a", "b", "&", "é", "\n"] {
                    texts.push(text.clone() + suffix);
                }
            }
        }
        texts.sort();
        texts.dedup();
        for pattern in [
            "a",
            "a|ab",
            "a.*b",
            "a.*?b",
            "a+",
            "a$",
            "^a",
            "(?m)^a",
            r"\ba\b",
            "é|éa",
            r"(?-u:\ba\b)",
        ] {
            let vm = PikeVM::builder()
                .configure(PikeVM::config().match_kind(MatchKind::All))
                .build(pattern)
                .unwrap();
            let nfa = vm.get_nfa();
            let mut cache = Cache::new(nfa);
            let mut reference_cache = vm.create_cache();
            for text in &texts {
                let boundaries = (0..=text.len())
                    .filter(|&i| text.is_char_boundary(i))
                    .collect::<Vec<_>>();
                let mut spans = Vec::new();
                if boundaries.len() > 1 {
                    spans.push(FieldSpan {
                        name: "first".into(),
                        range: 0..boundaries[1],
                    });
                    if boundaries.len() > 2 {
                        spans.push(FieldSpan {
                            name: "last".into(),
                            range: boundaries[boundaries.len() - 2]..text.len(),
                        });
                    }
                }
                let mut expected = Coverage::default();
                for &start in &boundaries {
                    for &end in boundaries.iter().filter(|&&end| end > start) {
                        if let Some(hit) = vm.find(
                            &mut reference_cache,
                            Input::new(text).span(start..end).anchored(Anchored::Yes),
                        ) {
                            if hit.start() == start && hit.end() == end {
                                if let Some(span) = spans
                                    .iter()
                                    .find(|span| span.range.start <= start && end <= span.range.end)
                                {
                                    expected.fields.insert(span.name.clone());
                                } else {
                                    expected.unscoped = true;
                                }
                            }
                        }
                    }
                }
                let actual = cache.scan(nfa, text, &spans).unwrap();
                assert_eq!(actual.unscoped, expected.unscoped, "{pattern:?}: {text:?}");
                if !actual.unscoped {
                    assert_eq!(actual.fields, expected.fields, "{pattern:?}: {text:?}");
                }
            }
        }
    }
}
