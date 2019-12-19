/*
 * Copyright (C) 2019 Open Whisper Systems
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

use std::time::{Duration};

use rand::Rng;

pub const NANOS_PER_SEC: u32 = 1_000_000_000;

pub fn random(max: Duration) -> Duration {
    let secs  = rand::thread_rng().gen_range(0, max.as_secs().saturating_add(1));
    let nanos = rand::thread_rng().gen_range(0, max.subsec_nanos().saturating_add(1));
    Duration::new(secs, nanos)
}

pub fn as_ticks(duration: Duration, tick_interval: Duration) -> u32 {
    let duration_ms      = duration.as_millis();
    let tick_interval_ms = tick_interval.as_millis();
    let ticks            = duration_ms.saturating_add(tick_interval_ms.saturating_sub(1))
                                      .checked_div(tick_interval_ms)
                                      .unwrap_or(0);
    ticks as u32
}

pub fn as_secs_f64(duration: Duration) -> f64 {
    (duration.as_secs() as f64) + (duration.subsec_nanos() as f64) / (NANOS_PER_SEC as f64)
}

#[cfg(test)]
mod test {
    use std::time::{Duration};

    use super::*;

    #[test]
    fn test_as_ticks() {
        let max_duration = Duration::new(u64::max_value(), NANOS_PER_SEC - 1);

        assert_eq!(as_ticks(Duration::from_secs(10),    Duration::from_secs(1)),      10);
        assert_eq!(as_ticks(Duration::from_secs(10),    Duration::from_secs(0)),      0);
        assert_eq!(as_ticks(Duration::from_millis(100), Duration::from_millis(10)),   10);
        assert_eq!(as_ticks(Duration::from_millis(100), Duration::from_millis(11)),   10);
        assert_eq!(as_ticks(Duration::from_millis(100), Duration::from_millis(12)),   9);
        assert_eq!(as_ticks(Duration::from_millis(100), Duration::from_millis(99)),   2);
        assert_eq!(as_ticks(Duration::from_millis(100), Duration::from_millis(100)),  1);
        assert_eq!(as_ticks(Duration::from_millis(100), Duration::from_millis(1000)), 1);

        assert_eq!(as_ticks(max_duration,           Duration::from_secs(0)), 0);
        assert_eq!(as_ticks(max_duration,           max_duration),           1);
        assert_eq!(as_ticks(Duration::from_secs(0), max_duration),           0);
        assert_eq!(as_ticks(Duration::from_secs(0), Duration::from_secs(0)), 0);

        assert_eq!(as_ticks(Duration::from_millis(1), max_duration), 1);
    }
}
