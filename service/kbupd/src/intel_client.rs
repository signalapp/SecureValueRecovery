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

use std::sync::Arc;

use hyper::client::HttpConnector;
use ias_client::IasClient;
use kbuptlsd::prelude::*;

pub type KbupdIasClient = IasClient<TlsProxyConnector<HttpConnector>>;

pub fn new_ias_client(host: &str, tls_proxy: TlsClientProxySpawner) -> Result<KbupdIasClient, failure::Error> {
    let mut http_connector = HttpConnector::new(1);
    http_connector.enforce_http(false);

    let tls_connector = TlsProxyConnector::new(Arc::new(tls_proxy), http_connector);

    IasClient::new(host, None, tls_connector)
}
