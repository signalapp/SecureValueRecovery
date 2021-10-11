//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::time::*;

use exponential_decay_histogram::Snapshot;
use failure::ResultExt;
use http::header::HeaderValue;
use http::uri;
use http::{HttpTryFrom, Uri};
use hyper::client::connect::Connect;
use hyper::{Body, Client, Method, Request};
use log::{debug, info, warn};
use nix::unistd;
use serde::ser::SerializeSeq;
use serde::{Serialize, Serializer};
use serde_derive::*;
use tokio::timer::Timeout;

use self::Point::*;

use super::*;

const GAUGE_TYPE: &str = "gauge";

#[derive(Default, Serialize)]
pub struct SubmitMetricsRequest {
    series: Vec<Series>,
}

#[derive(Serialize)]
struct Series {
    #[serde(flatten)]
    metadata: MetricMetadata,
    metric: String,
    points: Vec<Point>,

    #[serde(rename(serialize = "type"))]
    metric_type: &'static str,
}

#[derive(Clone, Serialize)]
struct MetricMetadata {
    host: String,
    tags: Vec<String>,
}

enum Point {
    UnsignedIntegerPoint { timestamp: u64, value: u64 },
    SignedIntegerPoint { timestamp: u64, value: i64 },
    DoublePoint { timestamp: u64, value: f64 },
}

impl Serialize for Point {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(2))?;

        match self {
            Point::UnsignedIntegerPoint { timestamp, value } => {
                seq.serialize_element(timestamp)?;
                seq.serialize_element(value)?;
            }

            Point::SignedIntegerPoint { timestamp, value } => {
                seq.serialize_element(timestamp)?;
                seq.serialize_element(value)?;
            }

            Point::DoublePoint { timestamp, value } => {
                seq.serialize_element(timestamp)?;
                seq.serialize_element(value)?;
            }
        }

        seq.end()
    }
}

impl SubmitMetricsRequest {
    pub fn from_registry(
        registry: &MetricRegistry,
        hostname: &str,
        environment: &str,
        partition: &Option<String>,
        role: &str,
        timestamp: u64,
    ) -> Self {
        let mut request = Self::default();

        let tags = {
            let mut tags = vec![
                String::from("service:kbupd"),
                "env:".to_owned() + environment,
                "role:".to_owned() + role,
            ];

            if let Some(partition) = partition {
                tags.push("partition:".to_owned() + partition);
            }

            tags
        };

        let metadata = MetricMetadata {
            host: String::from(hostname),
            tags,
        };

        for (metric_name, metric) in registry.metrics() {
            match metric {
                Metric::Counter(counter) => request.add_series(
                    metric_name,
                    UnsignedIntegerPoint {
                        timestamp,
                        value: counter.count(),
                    },
                    &metadata,
                ),
                Metric::Gauge(gauge) => request.add_series(
                    metric_name,
                    DoublePoint {
                        timestamp,
                        value: gauge.value(),
                    },
                    &metadata,
                ),
                Metric::Meter(meter) => request.add_series(
                    metric_name + ".count",
                    UnsignedIntegerPoint {
                        timestamp,
                        value: meter.count(),
                    },
                    &metadata,
                ),
                Metric::Histogram(histogram) => {
                    request.add_snapshot_series(metric_name, &histogram.snapshot(), timestamp, &metadata);
                }
                Metric::Timer(timer) => {
                    request.add_snapshot_series(metric_name, &timer.histogram().snapshot(), timestamp, &metadata);
                }
            };
        }

        request
    }

    fn add_snapshot_series(&mut self, base_name: String, snapshot: &Snapshot, timestamp: u64, metadata: &MetricMetadata) {
        self.add_series(
            base_name.clone() + ".count",
            UnsignedIntegerPoint {
                timestamp,
                value: snapshot.count(),
            },
            metadata,
        );
        self.add_series(
            base_name.clone() + ".max",
            SignedIntegerPoint {
                timestamp,
                value: snapshot.max(),
            },
            metadata,
        );
        self.add_series(
            base_name.clone() + ".mean",
            DoublePoint {
                timestamp,
                value: snapshot.mean(),
            },
            metadata,
        );
        self.add_series(
            base_name.clone() + ".min",
            SignedIntegerPoint {
                timestamp,
                value: snapshot.max(),
            },
            metadata,
        );
        self.add_series(
            base_name.clone() + ".stddev",
            DoublePoint {
                timestamp,
                value: snapshot.stddev(),
            },
            metadata,
        );
        self.add_series(
            base_name.clone() + ".median",
            SignedIntegerPoint {
                timestamp,
                value: snapshot.value(0.5),
            },
            metadata,
        );
        self.add_series(
            base_name.clone() + ".p75",
            SignedIntegerPoint {
                timestamp,
                value: snapshot.value(0.75),
            },
            metadata,
        );
        self.add_series(
            base_name.clone() + ".p95",
            SignedIntegerPoint {
                timestamp,
                value: snapshot.value(0.95),
            },
            metadata,
        );
        self.add_series(
            base_name.clone() + ".p98",
            SignedIntegerPoint {
                timestamp,
                value: snapshot.value(0.98),
            },
            metadata,
        );
        self.add_series(
            base_name.clone() + ".p99",
            SignedIntegerPoint {
                timestamp,
                value: snapshot.value(0.99),
            },
            metadata,
        );
        self.add_series(
            base_name.clone() + ".p999",
            SignedIntegerPoint {
                timestamp,
                value: snapshot.value(0.999),
            },
            metadata,
        );
    }

    fn add_series(&mut self, name: String, point: Point, metadata: &MetricMetadata) {
        self.series.push(Series {
            metadata: metadata.clone(),
            metric: name,
            points: vec![point],
            metric_type: GAUGE_TYPE,
        });
    }
}

pub struct JsonReporter<ConnectorTy> {
    uri: Uri,
    api_key: String,
    hostname: String,
    environment: String,
    partition: Option<String>,
    role: String,
    client: Client<ConnectorTy, Body>,
    runtime: tokio::runtime::Runtime,
}

impl<ConnectorTy> JsonReporter<ConnectorTy>
where
    ConnectorTy: Connect + 'static,
{
    pub fn new(
        api_key: &str,
        target_hostname: &str,
        maybe_our_hostname: Option<&str>,
        environment: &str,
        partition: &Option<String>,
        role: &str,
        connector: ConnectorTy,
    ) -> Result<Self, failure::Error> {
        let our_hostname = match maybe_our_hostname {
            Some(hostname) => String::from(hostname),
            None => {
                let mut hostname_buf = [0; 255];
                let hostname_cstr = unistd::gethostname(&mut hostname_buf).context("error getting hostname")?;

                hostname_cstr.to_string_lossy().into_owned()
            }
        };

        info!("starting json metrics reporter for {} as {}", target_hostname, our_hostname);

        let path_and_query = String::from("/api/v1/series");
        let mut uri_parts = uri::Parts::default();
        uri_parts.scheme = Some(uri::Scheme::HTTPS);
        uri_parts.authority = Some(uri::Authority::try_from(target_hostname).context("invalid hostname")?);
        uri_parts.path_and_query = Some(uri::PathAndQuery::try_from(path_and_query.as_str()).context("invalid token or host")?);
        let uri = Uri::try_from(uri_parts).context("invalid hostname, token, or host")?;

        let runtime = tokio::runtime::Builder::new()
            .core_threads(1)
            .name_prefix("json-reporter-")
            .build()
            .context("error starting tokio runtime for json-reporter")?;
        let client = Client::builder().executor(runtime.executor()).build(connector);

        Ok(Self {
            uri,
            api_key: String::from(api_key),
            hostname: our_hostname,
            environment: String::from(environment),
            partition: partition.as_ref().map(String::from),
            role: String::from(role),
            client,
            runtime, })
    }
}

impl<ConnectorTy> Reporter for JsonReporter<ConnectorTy>
where ConnectorTy: Connect + 'static
{
    fn report(&mut self, registry: &MetricRegistry) {
        debug!("reporting metrics...");

        let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(duration) => duration.as_secs(),
            Err(time_error) => {
                warn!("couldn't determine current time: {}", time_error);
                return;
            }
        };

        let request = SubmitMetricsRequest::from_registry(registry, &self.hostname, &self.environment, &self.partition, &self.role, now);
        let encoded_request = match serde_json::to_vec(&request) {
            Ok(encoded_request) => encoded_request,
            Err(serde_error) => {
                warn!("error encoding json metrics: {}", serde_error);
                return;
            }
        };

        let mut hyper_request = Request::new(Body::from(encoded_request));
        *hyper_request.method_mut() = Method::POST;
        *hyper_request.uri_mut() = self.uri.clone();
        hyper_request
            .headers_mut()
            .insert("Content-Type", HeaderValue::from_static("application/json"));

        match HeaderValue::from_str(&self.api_key) {
            Ok(header_value) => {
                hyper_request.headers_mut().insert("DD-API-KEY", header_value);
            }
            Err(e) => {
                warn!("invalid API key: {}", e);
                return;
            }
        };

        let response = Timeout::new(self.client.request(hyper_request), Duration::from_secs(30));

        match self.runtime.block_on(response) {
            Ok(response) => {
                if response.status().is_success() {
                    debug!("sent {} metrics successfully", request.series.len());
                } else {
                    info!("http error sending metrics: {}", response.status());
                }
            }
            Err(hyper_error) => {
                info!("error sending metrics: {}", hyper_error);
            }
        }
    }
}
