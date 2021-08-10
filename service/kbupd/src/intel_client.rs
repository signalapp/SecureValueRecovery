//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::sync::Arc;

use hyper::client::HttpConnector;
use ias_client::{IasApiVersion, IasClient};
use kbuptlsd::prelude::*;

pub type KbupdIasClient = IasClient<TlsProxyConnector<HttpConnector>>;

pub fn new_ias_client(host: &str, api_key: &str, tls_proxy: TlsClientProxySpawner) -> Result<KbupdIasClient, failure::Error> {
    let mut http_connector = HttpConnector::new(1);
    http_connector.enforce_http(false);

    let tls_connector = TlsProxyConnector::new(Arc::new(tls_proxy), http_connector);

    IasClient::new(host, Some(IasApiVersion::ApiVer4), Some(api_key), tls_connector)
}
