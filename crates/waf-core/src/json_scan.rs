//! Visit every JSON string/key without retaining a document tree.
use crate::profile::PolicyError;
use serde::de::{DeserializeSeed, Error, MapAccess, SeqAccess, Visitor};
use std::{borrow::Cow, collections::HashSet, fmt};

struct Key;
impl<'de> DeserializeSeed<'de> for Key {
    type Value = Cow<'de, str>;
    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        struct KeyVisitor;
        impl<'de> Visitor<'de> for KeyVisitor {
            type Value = Cow<'de, str>;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a JSON object key")
            }
            fn visit_borrowed_str<E: Error>(self, text: &'de str) -> Result<Self::Value, E> {
                Ok(Cow::Borrowed(text))
            }
            fn visit_str<E: Error>(self, text: &str) -> Result<Self::Value, E> {
                Ok(Cow::Owned(text.into()))
            }
            fn visit_string<E: Error>(self, text: String) -> Result<Self::Value, E> {
                Ok(Cow::Owned(text))
            }
        }
        d.deserialize_str(KeyVisitor)
    }
}

struct Strings<'a, F> {
    emit: &'a mut F,
}
impl<'de, F: FnMut(&str) -> Result<(), ()>> DeserializeSeed<'de> for Strings<'_, F> {
    type Value = ();
    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        d.deserialize_any(self)
    }
}
impl<'de, F: FnMut(&str) -> Result<(), ()>> Visitor<'de> for Strings<'_, F> {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("unambiguous JSON")
    }
    fn visit_bool<E: Error>(self, _: bool) -> Result<(), E> {
        Ok(())
    }
    fn visit_i64<E: Error>(self, _: i64) -> Result<(), E> {
        Ok(())
    }
    fn visit_u64<E: Error>(self, _: u64) -> Result<(), E> {
        Ok(())
    }
    fn visit_f64<E: Error>(self, n: f64) -> Result<(), E> {
        if n.is_finite() {
            Ok(())
        } else {
            Err(E::custom("invalid number"))
        }
    }
    fn visit_unit<E: Error>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_str<E: Error>(self, text: &str) -> Result<(), E> {
        (self.emit)(text).map_err(|_| E::custom("inspection view rejected"))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        while seq
            .next_element_seed(Strings { emit: self.emit })?
            .is_some()
        {}
        Ok(())
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        // Keys are retained only for the current object. Unescaped keys borrow input.
        // Randomized hashing prevents a caller-selected collision table; equality
        // checks decoded strings, so escaped duplicate spellings are rejected too.
        let mut keys = HashSet::new();
        while let Some(key) = map.next_key_seed(Key)? {
            if keys.contains(&key) {
                return Err(A::Error::custom("duplicate JSON key"));
            }
            (self.emit)(&key).map_err(|_| A::Error::custom("inspection view rejected"))?;
            keys.insert(key);
            map.next_value_seed(Strings { emit: self.emit })?;
        }
        Ok(())
    }
}

pub(crate) fn scan_strings(
    bytes: &[u8],
    mut emit: impl FnMut(&str) -> Result<(), PolicyError>,
) -> Result<(), PolicyError> {
    let mut emission_error = None;
    let mut callback = |text: &str| match emit(text) {
        Ok(()) => Ok(()),
        Err(error) => {
            emission_error = Some(error);
            Err(())
        }
    };
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let result = Strings {
        emit: &mut callback,
    }
    .deserialize(&mut deserializer)
    .and_then(|()| deserializer.end());
    result.map_err(|_| {
        emission_error.unwrap_or_else(|| PolicyError("invalid_or_ambiguous_json".into()))
    })
}
