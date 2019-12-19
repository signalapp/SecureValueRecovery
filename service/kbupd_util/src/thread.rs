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

use std::thread;
use std::thread::{JoinHandle};
use std::time::*;
use std::sync::*;

#[derive(Clone)]
pub struct StopJoinHandle<T> {
    stop_state:  Arc<StopState>,
    join_handle: Arc<Mutex<Option<JoinHandle<T>>>>,
}

#[derive(Default)]
pub struct StopState {
    condvar: Condvar,
    stopped: Mutex<bool>,
}

impl<T> StopJoinHandle<T> {
    pub fn new(stop_state: Arc<StopState>, join_handle: JoinHandle<T>) -> Self {
        Self {
            stop_state,
            join_handle: Arc::new(Mutex::new(Some(join_handle))),
        }
    }
    pub fn stop(&self) {
        let mut stopped_guard = match self.stop_state.stopped.lock() {
            Ok(guard)   => guard,
            Err(poison) => poison.into_inner(),
        };
        *stopped_guard = true;
        self.stop_state.condvar.notify_all();
    }
    pub fn join(&self) -> Option<thread::Result<T>> {
        let mut join_handle_guard = match self.join_handle.lock() {
            Ok(guard)   => guard,
            Err(poison) => poison.into_inner(),
        };
        if let Some(join_handle) = join_handle_guard.take() {
            Some(join_handle.join())
        } else {
            None
        }
    }
}
impl StopState {
    pub fn sleep_while_running(&self, duration: Duration) -> bool {
        let mut stopped_guard = match self.stopped.lock() {
            Ok(guard)   => guard,
            Err(poison) => poison.into_inner(),
        };
        let start = Instant::now();
        loop {
            if *stopped_guard {
                break false;
            }
            let timeout = match duration.checked_sub(start.elapsed()) {
                Some(timeout) => timeout,
                None          => break true,
            };
            stopped_guard = {
                let (stopped_guard, wait_timeout_result) = match self.condvar.wait_timeout(stopped_guard, timeout) {
                    Ok(result)  => result,
                    Err(poison) => poison.into_inner(),
                };
                if wait_timeout_result.timed_out() {
                    break !*stopped_guard;
                } else {
                    stopped_guard
                }
            };
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_stop_join() {
        let stop_state   = Arc::new(StopState::default());
        let stop_state_2 = stop_state.clone();
        let join_handle  = std::thread::spawn(move || {
            assert!(!stop_state.sleep_while_running(Duration::from_secs(60)));
        });
        let stop_join_handle = StopJoinHandle::new(stop_state_2, join_handle);
        stop_join_handle.stop();
        let () = stop_join_handle.join().unwrap().unwrap();
        assert!(stop_join_handle.join().is_none());
    }

    #[test]
    fn test_sleep_while_running() {
        let stop_state   = Arc::new(StopState::default());
        let stop_state_2 = stop_state.clone();
        let (tx, rx)     = std::sync::mpsc::channel();
        let join_handle  = std::thread::spawn(move || {
            assert!(stop_state.sleep_while_running(Duration::from_millis(1)));
            assert!(stop_state.sleep_while_running(Duration::from_millis(1)));
            let _ = tx.send(());
            assert!(!stop_state.sleep_while_running(Duration::from_secs(60)));
        });
        let stop_join_handle = StopJoinHandle::new(stop_state_2, join_handle);
        let () = rx.recv().unwrap();
        stop_join_handle.stop();
        let () = stop_join_handle.join().unwrap().unwrap();
    }
}
