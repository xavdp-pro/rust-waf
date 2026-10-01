//! Bounded local HTTP bans. This module never contacts upstream services.
use crate::profile::PolicyError;
use serde::Deserialize;
use std::{
    collections::HashMap,
    net::IpAddr,
    time::{Duration, Instant},
};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BanConfig {
    pub threshold: u32,
    pub window_seconds: u64,
    pub duration_seconds: u64,
    pub max_entries: usize,
}
impl Default for BanConfig {
    fn default() -> Self {
        Self {
            threshold: 3,
            window_seconds: 60,
            duration_seconds: 300,
            max_entries: 4096,
        }
    }
}
impl BanConfig {
    pub fn validate(&self) -> Result<(), PolicyError> {
        if !(2..=20).contains(&self.threshold)
            || !(1..=300).contains(&self.window_seconds)
            || !(1..=900).contains(&self.duration_seconds)
            || !(1..=65536).contains(&self.max_entries)
        {
            return Err(PolicyError("invalid_ban_bounds".into()));
        }
        Ok(())
    }
}
struct Entry {
    window_start: Instant,
    hits: u32,
    until: Option<Instant>,
}
pub struct BanTable {
    config: BanConfig,
    entries: HashMap<IpAddr, Entry>,
}
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v) => v.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        _ => ip,
    }
}
fn excluded(ip: IpAddr, trusted: bool) -> bool {
    trusted
        || match ip {
            IpAddr::V4(v) => {
                v.is_loopback()
                    || v.is_private()
                    || v.is_link_local()
                    || v.is_unspecified()
                    || v.is_multicast()
                    || v.is_broadcast()
            }
            IpAddr::V6(v) => {
                v.is_loopback()
                    || v.is_unspecified()
                    || v.is_multicast()
                    || (v.segments()[0] & 0xfe00) == 0xfc00
                    || (v.segments()[0] & 0xffc0) == 0xfe80
            }
        }
}
impl BanTable {
    pub fn new(config: BanConfig) -> Result<Self, PolicyError> {
        config.validate()?;
        Ok(Self {
            config,
            entries: HashMap::new(),
        })
    }
    pub fn remaining(&self, ip: IpAddr, trusted: bool, now: Instant) -> Option<Duration> {
        let ip = canonical(ip);
        if excluded(ip, trusted) {
            return None;
        }
        self.entries
            .get(&ip)?
            .until?
            .checked_duration_since(now)
            .filter(|d| !d.is_zero())
    }
    /// Only enforcement-mode, unexcepted high-confidence detections call this method.
    /// One request counts once, even if multiple reliable rules match.
    pub fn record_reliable(&mut self, ip: IpAddr, trusted: bool, now: Instant) -> bool {
        let ip = canonical(ip);
        if excluded(ip, trusted) {
            return false;
        }
        self.entries.retain(|_, e| match e.until {
            Some(until) => until > now,
            None => {
                now.duration_since(e.window_start) < Duration::from_secs(self.config.window_seconds)
            }
        });
        if !self.entries.contains_key(&ip) && self.entries.len() >= self.config.max_entries {
            // Exhaustion must not cause a global denial or displace an active ban.
            return false;
        }
        let entry = self.entries.entry(ip).or_insert(Entry {
            window_start: now,
            hits: 0,
            until: None,
        });
        if entry.until.is_some() {
            return false;
        }
        entry.hits = entry.hits.saturating_add(1);
        if entry.hits >= self.config.threshold {
            entry.until = Some(now + Duration::from_secs(self.config.duration_seconds));
            return true;
        }
        false
    }
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }
}
