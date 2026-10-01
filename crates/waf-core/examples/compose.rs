use std::{env, fs};
use waf_core::profile::{Profile, compose};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let site = args
        .next()
        .ok_or("usage: compose SITE_ID PROFILE.json ...")?;
    let profiles = args
        .map(|path| Profile::parse(&fs::read(path)?).map_err(Into::into))
        .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
    let policy = compose(profiles, &site)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "fingerprint": policy.fingerprint, "chain": policy.chain, "limits": policy.limits
        }))?
    );
    Ok(())
}
