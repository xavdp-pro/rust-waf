//! Synthetic single-request resource probe; use an external peak-RSS sampler.
use bytes::Bytes;
use waf_core::{
    inspect::normalize,
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
    let policy = compose(profiles, "example-site")?;
    let size = std::env::args()
        .nth(2)
        .map(|s| s.parse::<usize>())
        .transpose()?
        .unwrap_or(8 * 1024 * 1024);
    if !(128..=policy.limits.body_bytes).contains(&size) {
        return Err("invalid probe size".into());
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
    let views = normalize(&policy, "/fixture/", "", media, Bytes::from(body)).await?;
    println!(
        "{}",
        serde_json::json!({"case":case,"body_bytes":bytes,
        "body_views":views.body.len(), "retained_body_view_bytes":views.body.iter().map(String::len).sum::<usize>()})
    );
    Ok(())
}
