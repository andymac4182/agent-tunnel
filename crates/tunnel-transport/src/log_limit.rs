//! A bounded rate limit for refusal log lines an unauthenticated peer can
//! trigger (task row M6-C52, review of `m6-client`).
//!
//! A refusal line is written before the peer has proved anything -- a TLS
//! handshake with no or a self-signed client certificate, a request with no or
//! a junk bearer token -- so without a limit anyone who can reach a public
//! listener decides how fast the relay's `info` log grows.  Admission bounds
//! concurrency, not rate.  This limiter admits at most `burst` lines per
//! `window` for each fixed key (the refusal's stage or label), counts the rest,
//! and hands that count to the next admitted line for the key, which logs it
//! as `suppressed`.  During a sustained flood that is one line per key per
//! window carrying the previous window's suppressed count; when the flood
//! stops, the count is reported by the next refusal of that key.
//!
//! The state is one small entry per key, and keys are `&'static str` labels
//! the caller chooses from a closed set, so the limiter itself is bounded.

use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

/// Default: at most this many lines per key per window.
pub const DEFAULT_REFUSAL_LOG_BURST: u32 = 20;
/// Default window.
pub const DEFAULT_REFUSAL_LOG_WINDOW: Duration = Duration::from_secs(10);

/// A per-key fixed-window line budget.  See the module documentation.
#[derive(Debug)]
pub struct RefusalLogLimiter {
    burst: u32,
    window: Duration,
    keys: Mutex<HashMap<&'static str, Window>>,
}

#[derive(Debug)]
struct Window {
    started: Instant,
    admitted: u32,
    suppressed: u64,
}

impl RefusalLogLimiter {
    /// A limiter admitting `burst` lines per `window` for each key.
    #[must_use]
    pub fn new(burst: u32, window: Duration) -> Self {
        Self {
            burst,
            window,
            keys: Mutex::new(HashMap::new()),
        }
    }

    /// The limiter with the documented defaults.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(DEFAULT_REFUSAL_LOG_BURST, DEFAULT_REFUSAL_LOG_WINDOW)
    }

    /// Whether a line for `key` may be written now.  `Some(n)` admits it and
    /// carries the number of lines for this key suppressed since the last
    /// admitted one, which the caller logs; `None` suppresses it and counts
    /// it.
    pub fn admit(&self, key: &'static str) -> Option<u64> {
        self.admit_at(key, Instant::now())
    }

    /// [`RefusalLogLimiter::admit`] against an explicit clock.
    pub fn admit_at(&self, key: &'static str, now: Instant) -> Option<u64> {
        let mut keys = match self.keys.lock() {
            Ok(keys) => keys,
            // A panic elsewhere while holding the lock leaves only counters;
            // keep limiting rather than logging without a bound.
            Err(poisoned) => poisoned.into_inner(),
        };
        let entry = keys.entry(key).or_insert(Window {
            started: now,
            admitted: 0,
            suppressed: 0,
        });
        if now.saturating_duration_since(entry.started) >= self.window {
            entry.started = now;
            entry.admitted = 0;
        }
        if entry.admitted < self.burst {
            entry.admitted += 1;
            Some(std::mem::take(&mut entry.suppressed))
        } else {
            entry.suppressed = entry.suppressed.saturating_add(1);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A flood admits `burst` lines per window, suppresses the rest, and the
    /// first line of the next window reports how many were suppressed.  Keys
    /// are independent, so one flooded stage does not hide another.
    #[test]
    fn a_flood_is_bounded_per_window_and_reports_what_it_suppressed() {
        let limiter = RefusalLogLimiter::new(3, Duration::from_secs(10));
        let start = Instant::now();
        let admitted: Vec<_> = (0..1000)
            .filter_map(|_| limiter.admit_at("token", start))
            .collect();
        assert_eq!(admitted, vec![0, 0, 0], "three lines in the first window");
        assert_eq!(
            limiter.admit_at("bearer", start),
            Some(0),
            "keys are separate"
        );
        let later = start + Duration::from_secs(10);
        assert_eq!(limiter.admit_at("token", later), Some(997));
        assert_eq!(limiter.admit_at("token", later), Some(0));
    }
}
