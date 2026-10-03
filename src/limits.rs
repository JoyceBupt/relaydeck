use std::{collections::HashMap, net::IpAddr};

/// Bounded admission counters. Capacity pressure evicts the oldest counter;
/// it never rejects an unrelated key or shares anonymous and authenticated budgets.
pub struct Limits {
    entries: HashMap<String, (i64, u32)>,
    capacity: usize,
}

impl Limits {
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: HashMap::new(),
            capacity,
        }
    }

    pub fn reset(&mut self, key: &str) {
        self.entries.remove(key);
    }

    pub fn admit(&mut self, key: String, maximum: u32, timestamp: i64) -> bool {
        self.entries
            .retain(|_, (start, _)| timestamp.saturating_sub(*start) < 60);
        if let Some((_, count)) = self.entries.get_mut(&key) {
            if *count >= maximum {
                return false;
            }
            *count += 1;
            return true;
        }
        if self.entries.len() >= self.capacity
            && let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, (start, _))| start)
                .map(|(key, _)| key.clone())
        {
            self.entries.remove(&oldest);
        }
        self.entries.insert(key, (timestamp, 1));
        true
    }
}

pub fn network_key(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(ip) => ip.to_string(),
        IpAddr::V6(ip) => match ip.to_ipv4_mapped() {
            Some(ip) => ip.to_string(),
            None => format!("{:x}/64", u128::from(ip) >> 64),
        },
    }
}
