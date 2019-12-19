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

mod json_reporter;
#[macro_use]
mod macros;
mod metrics;
mod registry;
mod reporter;

pub use json_reporter::*;
pub use metrics::*;
pub use registry::*;
pub use reporter::*;

use crate::constants;

lazy_static::lazy_static! {
    pub static ref METRICS: MetricRegistry = MetricRegistries::global().get_or_create(constants::METRICS_NAME);
}

pub fn metric_name<T: AsRef<str>>(parts: impl IntoIterator<Item = T> + Clone) -> String {
    let name_len = parts.clone().into_iter().map(|part| part.as_ref().len() + 1).sum();
    let mut name = String::with_capacity(name_len);
    for part in parts {
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(part.as_ref());
    }
    name
}
