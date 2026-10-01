#[test]
fn real_http_transport_and_correlated_backend_proof() {
    let output = std::process::Command::new("python3")
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/transport.py"))
        .arg(env!("CARGO_BIN_EXE_waf-proxy"))
        .output()
        .expect("Python 3 must be installed for protocol evidence");
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    print!("{}", String::from_utf8_lossy(&output.stdout));
}
