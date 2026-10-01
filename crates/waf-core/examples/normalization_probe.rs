//! Synthetic single-request resource probe; default to the production scan path.
use bytes::Bytes;
use waf_core::{
    inspect::{Inspector, normalize},
    profile::{Profile, compose},
};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let case = std::env::args().nth(1).ok_or("supply a synthetic case")?;
    let profiles = [
        include_bytes!("../../../profiles/core/base.json").as_slice(),
        include_bytes!("../../../profiles/wordpress/base.json").as_slice(),
        include_bytes!("../../../profiles/sites/example.json").as_slice(),
    ]
    .into_iter()
    .map(Profile::parse)
    .collect::<Result<Vec<_>, _>>()?;
    let inspector = Inspector::new(compose(profiles, "example-site")?)?;
    let policy = &inspector.policy;
    let size = std::env::args()
        .nth(2)
        .map(|s| s.parse::<usize>())
        .transpose()?
        .unwrap_or(8 * 1024 * 1024);
    if !(128..=policy.limits.body_bytes).contains(&size) {
        return Err("invalid probe size".into());
    }
    let mode = std::env::args().nth(3).unwrap_or_else(|| "streamed".into());
    if !matches!(mode.as_str(), "streamed" | "collected") {
        return Err("invalid inspection mode".into());
    }
    let (media, body) = match case.as_str() {
        "opaque-text" => ("text/plain", vec![b'a'; size]),
        "opaque-binary" => ("application/octet-stream", vec![0xff; size]),
        "form" => ("application/x-www-form-urlencoded", vec![b'a'; size]),
        "json-string" => {
            let mut bytes = vec![b'a'; size];
            bytes[0] = b'"';
            bytes[size - 1] = b'"';
            ("application/json", bytes)
        }
        "json-nodes" => {
            let count = (size - 2) / 3;
            let mut bytes = Vec::with_capacity(size);
            bytes.push(b'[');
            for n in 0..count {
                if n != 0 {
                    bytes.push(b',');
                }
                bytes.extend_from_slice(b"[]");
            }
            bytes.push(b']');
            ("application/json", bytes)
        }
        "json-unique-strings" | "json-object-keys" | "json-empty-strings" => {
            let object = case == "json-object-keys";
            let mut bytes = Vec::with_capacity(size);
            bytes.push(if object { b'{' } else { b'[' });
            for n in 0usize.. {
                let value = if object {
                    format!("\"k{n:06}\":0")
                } else if case == "json-empty-strings" {
                    "\"\"".into()
                } else {
                    format!("\"v{n:06}\"")
                };
                if bytes.len() + value.len() + usize::from(n != 0) + 1 > size {
                    break;
                }
                if n != 0 {
                    bytes.push(b',');
                }
                bytes.extend_from_slice(value.as_bytes());
            }
            bytes.push(if object { b'}' } else { b']' });
            bytes.resize(size, b' ');
            ("application/json", bytes)
        }
        "multipart-binary" => {
            let head = b"--fixture\r\nContent-Disposition: form-data; name=\"file\"; filename=\"example.bin\"\r\n\r\n";
            let tail = b"\r\n--fixture--\r\n";
            let mut bytes = Vec::with_capacity(size);
            bytes.extend_from_slice(head);
            bytes.resize(size - tail.len(), 0xff);
            bytes.extend_from_slice(tail);
            ("multipart/form-data; boundary=fixture", bytes)
        }
        _ => return Err("unknown synthetic case".into()),
    };
    let bytes = body.len();
    let (views, matches) = if mode == "streamed" {
        let scanned = inspector
            .scan("/fixture/", "", media, Bytes::from(body))
            .await?;
        let matches = inspector.inspect_scanned(&scanned, "POST").len();
        (scanned.views, matches)
    } else {
        let views = normalize(policy, "/fixture/", "", media, Bytes::from(body)).await?;
        let matches = inspector.inspect(&views, "POST").len();
        (views, matches)
    };
    println!(
        "{}",
        serde_json::json!({"case":case,"body_bytes":bytes,"inspection_mode":mode,"rule_matches":matches,
        "body_views":views.body.len(), "retained_body_view_bytes":views.body.iter().map(String::len).sum::<usize>()})
    );
    Ok(())
}
