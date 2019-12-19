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

use std::net::{ToSocketAddrs};

use futures::prelude::*;
use hyper;
use hyper::{Server};
use hyper::server;
use hyper::server::conn::{AddrIncoming};

use crate::*;

pub struct ApiListener<Service> {
    service: Service,
    hyper:   server::Builder<AddrIncoming>,
}

impl<Service> ApiListener<Service>
where Service: hyper::service::Service<ResBody = hyper::body::Body,
                                       ReqBody = hyper::body::Body>,
      Service: Clone + Send + 'static,
      <Service as hyper::service::Service>::Future: Send,
{
    pub fn new(bind_address: impl ToSocketAddrs, service: Service) -> Result<Self, failure::Error> {
        let hyper =
            Server::try_bind(&util::to_socket_addr(bind_address)?)?
            .http1_only(true);
        Ok(Self {
            service,
            hyper,
        })
    }

    pub fn into_future(self) -> impl Future<Item = (), Error = ()> {
        let Self { service, hyper } = self;
        let server = hyper.serve(move || {
            let service: Result<Service, failure::Error> = Ok(service.clone());
            service
        });

        server.map_err(|error: hyper::Error| {
            error!("hyper server error: {}", error);
        })
    }
}
