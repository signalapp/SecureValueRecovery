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

use std::sync::*;
use std::thread;
use std::time::*;

use super::*;
use crate::util::thread::{StopJoinHandle, StopState};

pub trait Reporter: Send {
    fn report(&mut self, registry: &MetricRegistry);
}

pub struct PeriodicReporter<ReporterTy> {
    reporter:   ReporterTy,
    registry:   MetricRegistry,
    interval:   Duration,
    stop_state: Arc<StopState>,
}

impl<ReporterTy> PeriodicReporter<ReporterTy>
where ReporterTy: Reporter + 'static,
{
    pub fn new(reporter: ReporterTy, registry: MetricRegistry, interval: Duration) -> Self {
        Self {
            reporter,
            registry,
            interval,
            stop_state: Default::default(),
        }
    }

    pub fn start(mut self) -> StopJoinHandle<()> {
        let stop_state  = self.stop_state.clone();
        let join_handle = thread::spawn(move || {
            while self.stop_state.sleep_while_running(self.interval) {
                self.reporter.report(&self.registry);
            }
        });
        StopJoinHandle::new(stop_state, join_handle)
    }
}
