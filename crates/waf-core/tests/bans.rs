use std::{
    net::IpAddr,
    time::{Duration, Instant},
};
use waf_core::ban::{BanConfig, BanTable};
fn config() -> BanConfig {
    BanConfig {
        threshold: 3,
        window_seconds: 10,
        duration_seconds: 20,
        max_entries: 2,
    }
}
#[test]
fn bans_require_repeated_reliable_requests_expire_and_do_not_extend() {
    let mut table = BanTable::new(config()).unwrap();
    let now = Instant::now();
    let ip: IpAddr = "198.51.100.25".parse().unwrap();
    assert!(!table.record_reliable(ip, false, now));
    assert!(!table.record_reliable(ip, false, now));
    assert!(table.record_reliable(ip, false, now));
    assert_eq!(
        table.remaining(ip, false, now),
        Some(Duration::from_secs(20))
    );
    assert!(!table.record_reliable(ip, false, now + Duration::from_secs(5)));
    assert_eq!(
        table.remaining(ip, false, now + Duration::from_secs(5)),
        Some(Duration::from_secs(15))
    );
    assert!(
        table
            .remaining(ip, false, now + Duration::from_secs(20))
            .is_none()
    );
    assert!(!table.record_reliable(ip, false, now + Duration::from_secs(20)));
}
#[test]
fn trusted_infrastructure_and_mapped_addresses_are_handled() {
    let mut table = BanTable::new(config()).unwrap();
    let now = Instant::now();
    for text in [
        "127.0.0.1",
        "10.0.0.1",
        "169.254.1.1",
        "::1",
        "fc00::1",
        "fe80::1",
        "::ffff:127.0.0.1",
    ] {
        let ip = text.parse().unwrap();
        for _ in 0..4 {
            assert!(!table.record_reliable(ip, false, now));
        }
        assert!(table.remaining(ip, false, now).is_none());
    }
    let ip = "198.51.100.25".parse().unwrap();
    for _ in 0..4 {
        assert!(!table.record_reliable(ip, true, now));
    }
    let mapped = "::ffff:198.51.100.25".parse().unwrap();
    for _ in 0..3 {
        table.record_reliable(mapped, false, now);
    }
    assert!(table.remaining(ip, false, now).is_some());
    assert!(table.remaining(ip, true, now).is_none());
}
#[test]
fn window_and_capacity_are_bounded() {
    let mut table = BanTable::new(config()).unwrap();
    let now = Instant::now();
    let first = "198.51.100.1".parse().unwrap();
    let second = "198.51.100.2".parse().unwrap();
    let third = "198.51.100.3".parse().unwrap();
    table.record_reliable(first, false, now);
    table.record_reliable(second, false, now);
    for _ in 0..4 {
        assert!(!table.record_reliable(third, false, now));
    }
    assert_eq!(table.entry_count(), 2);
    assert!(!table.record_reliable(first, false, now + Duration::from_secs(10)));
    assert_eq!(table.entry_count(), 1);
}
#[test]
fn ban_configuration_cannot_be_unbounded_or_single_hit() {
    let mut value = config();
    value.threshold = 1;
    assert!(BanTable::new(value).is_err());
    let mut value = config();
    value.duration_seconds = 901;
    assert!(BanTable::new(value).is_err());
    let mut value = config();
    value.max_entries = 0;
    assert!(BanTable::new(value).is_err());
}
