use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Mutex;
use std::time::Instant;

use rand::seq::SliceRandom;

/// Unbound-style RTT band width in milliseconds.
/// Servers within min_rtt + BAND are considered equally good.
const RTT_BAND_MS: f64 = 100.0;
/// EWMA smoothing factor: 87.5% history, 12.5% new measurement.
const EWMA_WEIGHT: f64 = 7.0 / 8.0;
/// Penalty RTT assigned on timeout/failure (ms).
const TIMEOUT_PENALTY_MS: f64 = 5000.0;
/// Stats older than this are expired so the server gets re-probed.
const STATS_EXPIRE_SECS: u64 = 900;

struct RttStats {
    rtt: f64,
    last_update: Instant,
}

/// Adaptive server selection using Unbound-style RTT banding.
///
/// Tracks smoothed RTT per key and selects servers by grouping them into
/// a "preferred" band (within `RTT_BAND_MS` of the fastest known server)
/// and a "fallback" group. Unknown or expired servers are treated as
/// preferred so they get probed.
pub struct RttTracker<K: Eq + Hash + Clone> {
    stats: Mutex<HashMap<K, RttStats>>,
}

impl<K: Eq + Hash + Clone> RttTracker<K> {
    pub fn new() -> Self {
        RttTracker {
            stats: Mutex::new(HashMap::new()),
        }
    }

    /// Returns `keys` reordered for adaptive selection.
    ///
    /// - Keys with no stats or expired stats go to the preferred group (to be probed).
    /// - Known keys within `min_rtt + RTT_BAND_MS` go to the preferred group.
    /// - The rest are fallback.
    /// - Each group is shuffled; preferred comes first.
    pub fn select_ordered(&self, keys: &[K]) -> Vec<K> {
        let now = Instant::now();
        let stats = self.stats.lock().unwrap();

        let mut known: Vec<(K, f64)> = Vec::new();
        let mut unknown: Vec<K> = Vec::new();
        for key in keys {
            match stats.get(key) {
                Some(s) if now.duration_since(s.last_update).as_secs() < STATS_EXPIRE_SECS => {
                    known.push((key.clone(), s.rtt));
                }
                _ => {
                    unknown.push(key.clone());
                }
            }
        }
        drop(stats);

        let mut rng = rand::thread_rng();

        if known.is_empty() {
            unknown.shuffle(&mut rng);
            return unknown;
        }

        let min_rtt = known.iter().map(|(_, rtt)| *rtt).fold(f64::INFINITY, f64::min);
        let band_threshold = min_rtt + RTT_BAND_MS;

        let mut preferred: Vec<K> = Vec::new();
        let mut fallback: Vec<K> = Vec::new();
        for (key, rtt) in known {
            if rtt <= band_threshold {
                preferred.push(key);
            } else {
                fallback.push(key);
            }
        }

        preferred.extend(unknown);
        preferred.shuffle(&mut rng);
        fallback.shuffle(&mut rng);
        preferred.extend(fallback);
        preferred
    }

    /// Record a successful query with the measured RTT in milliseconds.
    pub fn record_success(&self, key: &K, rtt_ms: f64) {
        self.update(key, rtt_ms);
    }

    /// Record a failed/timed-out query, applying a penalty RTT.
    pub fn record_failure(&self, key: &K) {
        self.update(key, TIMEOUT_PENALTY_MS);
    }

    fn update(&self, key: &K, rtt_ms: f64) {
        let mut stats = self.stats.lock().unwrap();
        let entry = stats.entry(key.clone()).or_insert(RttStats {
            rtt: rtt_ms,
            last_update: Instant::now(),
        });
        entry.rtt = entry.rtt * EWMA_WEIGHT + rtt_ms * (1.0 - EWMA_WEIGHT);
        entry.last_update = Instant::now();
    }
}
