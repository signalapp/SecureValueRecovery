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

#![allow(non_snake_case)]

use std::io::{Read};

use serde_derive::{Deserialize};
use serde_yaml;

use crate::base64;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub client: Option<ClientConfig>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    pub clientCertificatePkcs12: Option<Base64ConfigValue>,

    pub caCertificates: Vec<ClientCaCertificateConfig>,

    pub hostnameValidation: ClientHostnameValidationConfig,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Base64ConfigValue(
    #[serde(with = "base64")]
    pub Vec<u8>
);

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ClientCaCertificateConfig {
    System,
    CustomPem(String),
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ClientHostnameValidationConfig {
    AcceptInvalid,
    Hostname(String),
}

//
// Config impls
//

impl Config {
    pub fn from_reader(reader: impl Read) -> Result<Self, failure::Error> {
        Ok(serde_yaml::from_reader(reader)?)
    }
}
