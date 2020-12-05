//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::ops::Deref;
use std::sync::Arc;

use futures::future;
use futures::prelude::*;
use http::header;
use http::header::HeaderValue;
use http::request;
use hyper::{Body, Chunk, Method, Request, Response, StatusCode};
use kbupd_api::entities::*;
use kbupd_macro::lazy_init;
use serde::{Deserialize, Serialize};
use try_future::TryFuture;

use super::auth::anonymous_user::*;
use super::auth::signal_user::*;
use super::auth::*;
use super::*;
use crate::limits::rate_limiter::*;
use crate::metrics::*;
use crate::*;

#[derive(Clone)]
pub struct SignalApiService<BackupManagerTy>
where BackupManagerTy: Clone
{
    router:                    route_recognizer::Router<Box<dyn ApiHandler<ApiService = Self>>>,
    backup_manager:            BackupManagerTy,
    deny_backup:               bool,
    rate_limiters:             SignalApiRateLimiters,
    signal_user_authenticator: Arc<SignalUserAuthenticator>,
}

#[derive(Clone)]
pub struct SignalApiRateLimiters {
    pub token:       actor::Sender<RateLimiter>,
    pub attestation: actor::Sender<RateLimiter>,
    pub backup:      actor::Sender<RateLimiter>,
}

lazy_init! {
    fn init_metrics() {
        static ref AUTHENTICATION_FAILED_METER:    Meter = METRICS.metric(&metric_name!("authentication", "failed"));
        static ref AUTHENTICATION_SUCCEEDED_METER: Meter = METRICS.metric(&metric_name!("authentication", "succeeded"));
        static ref HTTP_OK_METER:                  Meter = METRICS.metric(&metric_name!("http_ok"));
        static ref HTTP_4XX_METER:                 Meter = METRICS.metric(&metric_name!("http_4xx"));
        static ref HTTP_5XX_METER:                 Meter = METRICS.metric(&metric_name!("http_5xx"));
        static ref HANDLER_ERROR_METER:            Meter = METRICS.metric(&metric_name!("handler_error"));
        static ref GET_TOKEN_TIMER:                Timer = METRICS.metric(&metric_name!("get_token"));
        static ref GET_ATTESTATION_TIMER:          Timer = METRICS.metric(&metric_name!("get_attestation"));
        static ref PUT_BACKUP_REQUEST_TIMER:       Timer = METRICS.metric(&metric_name!("put_backup_request"));
        static ref DELETE_BACKUPS_TIMER:           Timer = METRICS.metric(&metric_name!("delete_backups"));
    }
}

impl<BackupManagerTy> SignalApiService<BackupManagerTy>
where BackupManagerTy: BackupManager<User = SignalUser> + Clone + Send + 'static
{
    pub fn new(
        signal_user_authenticator: Arc<SignalUserAuthenticator>,
        backup_manager: BackupManagerTy,
        deny_backup: bool,
        rate_limiters: SignalApiRateLimiters,
    ) -> Self
    {
        init_metrics();

        let mut router = route_recognizer::Router::new();

        router.add(
            "/v1/ping",
            Self::api_handler(move |_service, _params, request| match *request.method() {
                Method::GET => Some(Self::get_request_handler(
                    &AnonymousUserAuthenticator,
                    |service, _params, user, request| service.ping(user, request),
                )),
                _ => None,
            }),
        );
        router.add(
            "/v1/token/:enclave_name",
            Self::api_handler(move |service, _params, request| match *request.method() {
                Method::GET => Some(Self::get_request_handler(
                    service.signal_user_authenticator.clone(),
                    |service, params, user, request| service.get_token(&params["enclave_name"], user, request),
                )),
                _ => None,
            }),
        );
        router.add(
            "/v1/attestation/:enclave_name",
            Self::api_handler(move |service, _params, request| match *request.method() {
                Method::PUT => Some(Self::request_handler(
                    service.signal_user_authenticator.clone(),
                    |service, params, _parts, user, request| service.get_attestation(&params["enclave_name"], user, request),
                )),
                _ => None,
            }),
        );
        router.add(
            "/v1/backup/:enclave_name",
            Self::api_handler(move |service, _params, request| match *request.method() {
                Method::PUT => Some(Self::request_handler(
                    service.signal_user_authenticator.clone(),
                    |service, params, _parts, user, request| service.put_backup_request(&params["enclave_name"], user, request),
                )),
                _ => None,
            }),
        );
        router.add(
            "/v1/backup",
            Self::api_handler(move |service, _params, request| match *request.method() {
                Method::DELETE => Some(Self::get_request_handler(
                    service.signal_user_authenticator.clone(),
                    |service, _params, user, request| service.delete_backups(user, request),
                )),
                _ => None,
            }),
        );
        Self {
            router,
            backup_manager,
            deny_backup,
            signal_user_authenticator,
            rate_limiters,
        }
    }

    fn ping(
        &self,
        _user: AnonymousUser,
        _request: Request<Body>,
    ) -> impl Future<Item = Result<PingResponse, Response<Body>>, Error = failure::Error>
    {
        Ok(Ok(PingResponse {})).into_future()
    }

    fn get_token(
        &self,
        enclave_name: &str,
        user: SignalUser,
        _request: Request<Body>,
    ) -> impl Future<Item = Result<GetTokenResponse, Response<Body>>, Error = failure::Error>
    {
        let timer = GET_TOKEN_TIMER.time();
        let username = user.username.clone();
        let limit = self
            .rate_limiters
            .token
            .sync_call(move |rate_limiter: &mut RateLimiter| Self::handle_ratelimit_result(rate_limiter.validate(&username, 1)));
        let result = self.backup_manager.get_token(enclave_name.to_string(), &user);
        let response = result.then(move |result: Result<GetTokenResponse, EnclaveTransactionError>| {
            timer.stop();
            match result {
                Ok(response) => Ok(Ok(response)),
                Err(EnclaveTransactionError::EnclaveNotFound) => {
                    let mut response = Response::default();
                    *response.status_mut() = StatusCode::NOT_FOUND;
                    Ok(Err(response))
                }
                Err(error) => Err(error.into()),
            }
        });
        limit.and_then(|maybe_ratelimit_response: Option<Response<Body>>| match maybe_ratelimit_response {
            Some(ratelimit_response) => TryFuture::from_ok(Err(ratelimit_response)),
            None => response.into(),
        })
    }

    fn get_attestation(
        &self,
        enclave_name: &str,
        user: SignalUser,
        request: RemoteAttestationRequest,
    ) -> impl Future<Item = Result<RemoteAttestationResponse, Response<Body>>, Error = failure::Error>
    {
        let timer = GET_ATTESTATION_TIMER.time();
        let username = user.username.clone();
        let limit = self
            .rate_limiters
            .attestation
            .sync_call(move |rate_limiter: &mut RateLimiter| Self::handle_ratelimit_result(rate_limiter.validate(&username, 1)));
        let result = self.backup_manager.get_attestation(enclave_name.to_string(), &user, request);
        let response = result.then(|result: Result<RemoteAttestationResponse, RemoteAttestationError>| {
            timer.stop();
            match result {
                Ok(response) => Ok(Ok(response)),
                Err(RemoteAttestationError::EnclaveNotFound) => {
                    let mut response = Response::default();
                    *response.status_mut() = StatusCode::NOT_FOUND;
                    Ok(Err(response))
                }
                Err(RemoteAttestationError::InvalidInput) => {
                    let mut response = Response::default();
                    *response.status_mut() = StatusCode::BAD_REQUEST;
                    Ok(Err(response))
                }
                Err(error) => Err(error.into()),
            }
        });
        limit.and_then(|maybe_ratelimit_response: Option<Response<Body>>| match maybe_ratelimit_response {
            Some(ratelimit_response) => TryFuture::from_ok(Err(ratelimit_response)),
            None => response.into(),
        })
    }

    fn put_backup_request(
        &self,
        enclave_name: &str,
        user: SignalUser,
        request: KeyBackupRequest,
    ) -> impl Future<Item = Result<KeyBackupResponse, Response<Body>>, Error = failure::Error>
    {
        let timer = PUT_BACKUP_REQUEST_TIMER.time();
        let username = user.username.clone();
        match &request.r#type {
            KeyBackupRequestType::Backup if self.deny_backup => {
                let mut response = Response::<Body>::default();
                *response.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
                return future::Either::A(Ok(Err(response)).into_future());
            }
            _ => (),
        }
        let limit = self
            .rate_limiters
            .backup
            .sync_call(move |rate_limiter: &mut RateLimiter| Self::handle_ratelimit_result(rate_limiter.validate(&username, 1)));
        let result = self.backup_manager.put_backup_request(enclave_name.to_string(), &user, request);
        let response = result.then(|result: Result<KeyBackupResponse, KeyBackupError>| {
            timer.stop();
            match result {
                Ok(response) => Ok(Ok(response)),
                Err(KeyBackupError::EnclaveNotFound) => {
                    let mut response = Response::default();
                    *response.status_mut() = StatusCode::NOT_FOUND;
                    Ok(Err(response))
                }
                Err(KeyBackupError::InvalidInput) => {
                    let mut response = Response::new(Body::from("InvalidInput"));
                    *response.status_mut() = StatusCode::BAD_REQUEST;
                    Ok(Err(response))
                }
                Err(KeyBackupError::MacMismatch) => {
                    let mut response = Response::new(Body::from("MacMismatch"));
                    *response.status_mut() = StatusCode::BAD_REQUEST;
                    Ok(Err(response))
                }
                Err(KeyBackupError::PendingRequestIdNotFound) => {
                    let mut response = Response::default();
                    *response.status_mut() = StatusCode::GONE;
                    Ok(Err(response))
                }
                Err(error) => Err(error.into()),
            }
        });
        let response = limit.and_then(|maybe_ratelimit_response: Option<Response<Body>>| match maybe_ratelimit_response {
            Some(ratelimit_response) => TryFuture::from_ok(Err(ratelimit_response)),
            None => response.into(),
        });
        future::Either::B(response)
    }

    fn delete_backups(
        &self,
        user: SignalUser,
        _request: Request<Body>,
    ) -> impl Future<Item = Result<(), Response<Body>>, Error = failure::Error>
    {
        let timer = DELETE_BACKUPS_TIMER.time();
        let username = user.username.clone();

        let limit = self
            .rate_limiters
            .backup
            .sync_call(move |rate_limiter: &mut RateLimiter| Self::handle_ratelimit_result(rate_limiter.validate(&username, 1)));

        let result = self.backup_manager.delete_backups(&user);

        let response = result.then(|result: Result<(), EnclaveTransactionError>| {
            timer.stop();

            match result {
                Ok(response) => Ok(Ok(response)),
                Err(_) => {
                    let mut response = Response::default();
                    *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                    Ok(Err(response))
                }
            }
        });

        limit.and_then(|maybe_ratelimit_response: Option<Response<Body>>| match maybe_ratelimit_response {
            Some(ratelimit_response) => TryFuture::from_ok(Err(ratelimit_response)),
            None => response.into(),
        })
    }

    fn api_handler<F, H>(handler: F) -> Box<dyn ApiHandler<ApiService = Self>>
    where
        F: Fn(&Self, &route_recognizer::Params, &Request<Body>) -> Option<H> + Send + Clone + 'static,
        H: ApiHandler<ApiService = Self>,
    {
        Box::new(SignalApiHandler::new(
            move |service: &Self, params: route_recognizer::Params, request: Request<Body>| match handler(service, &params, &request) {
                Some(request_handler) => future::Either::A(request_handler.handle(service, params, request)),
                None => {
                    let mut response = Response::default();
                    *response.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
                    future::Either::B(Ok(response).into_future())
                }
            },
        ))
    }

    fn get_request_handler<AuthTy, ResTy, F, FRes>(
        authenticator: impl Deref<Target = AuthTy> + Clone + Send + Sync + 'static,
        handler: F,
    ) -> impl ApiHandler<ApiService = Self>
    where
        ResTy: Serialize + 'static,
        AuthTy: Authenticator,
        F: Fn(&Self, &route_recognizer::Params, AuthTy::User, Request<Body>) -> FRes + Send + Clone + 'static,
        FRes: Future<Item = Result<ResTy, Response<Body>>, Error = failure::Error> + Send + 'static,
    {
        SignalApiHandler::new(move |service: &Self, params: route_recognizer::Params, request: Request<Body>| {
            let user = match Self::authorize_request(&*authenticator, &request) {
                Err(error_response) => {
                    return future::Either::A(Ok(error_response).into_future());
                }
                Ok(user) => user,
            };

            let handler_result = handler(service, &params, user, request);
            let response = handler_result.then(Self::handle_result);
            future::Either::B(response)
        })
    }

    fn request_handler<AuthTy, ReqTy, ResTy, F, FRes>(
        authenticator: impl Deref<Target = AuthTy> + Clone + Send + Sync + 'static,
        handler: F,
    ) -> impl ApiHandler<ApiService = Self>
    where
        ReqTy: for<'de> Deserialize<'de> + Send + 'static,
        ResTy: Serialize + 'static,
        AuthTy: Authenticator,
        F: Fn(&Self, &route_recognizer::Params, request::Parts, AuthTy::User, ReqTy) -> FRes + Send + Clone + 'static,
        FRes: Future<Item = Result<ResTy, Response<Body>>, Error = failure::Error> + Send + 'static,
    {
        SignalApiHandler::new(move |service: &Self, params: route_recognizer::Params, request: Request<Body>| {
            let user = match Self::authorize_request(&*authenticator, &request) {
                Err(error_response) => {
                    return future::Either::A(Ok(error_response).into_future());
                }
                Ok(user) => user,
            };

            let service = service.clone();
            let handler = handler.clone();
            let read_result = Self::read_request(request);
            let response = read_result.and_then(move |read_result: Result<(request::Parts, ReqTy), Response<Body>>| {
                let (request_parts, request) = match read_result {
                    Ok(ok_result) => ok_result,
                    Err(error_response) => return future::Either::A(Ok(error_response).into_future()),
                };

                let handler_result = handler(&service, &params, request_parts, user, request);
                let response = handler_result.then(Self::handle_result);
                future::Either::B(response)
            });
            future::Either::B(response)
        })
    }

    fn authorize_request<AuthTy>(authenticator: &AuthTy, request: &Request<Body>) -> Result<AuthTy::User, Response<Body>>
    where AuthTy: Authenticator {
        let credentials = if let Some(header) = request.headers().get(hyper::header::AUTHORIZATION) {
            match BasicCredentials::try_from(header) {
                Err(_) => {
                    let mut response = Response::default();
                    *response.status_mut() = StatusCode::BAD_REQUEST;
                    return Err(response);
                }
                Ok(credentials) => Some(credentials),
            }
        } else {
            None
        };
        match authenticator.authenticate(credentials) {
            Err(_) => {
                AUTHENTICATION_FAILED_METER.mark();
                let mut response = Response::default();
                *response.status_mut() = StatusCode::UNAUTHORIZED;
                Err(response)
            }
            Ok(user) => {
                AUTHENTICATION_SUCCEEDED_METER.mark();
                Ok(user)
            }
        }
    }

    fn handle_ratelimit_result(result: Result<(), RateLimitError>) -> Result<Option<Response<Body>>, failure::Error> {
        match result {
            Ok(()) => Ok(None),
            Err(RateLimitError::Exceeded(exceeded_error)) => {
                let mut response = Response::new(Body::from(format!("{}", exceeded_error)));
                *response.status_mut() = StatusCode::TOO_MANY_REQUESTS;
                Ok(Some(response))
            }
            Err(error @ RateLimitError::InternalError) => Err(error.into()),
        }
    }

    fn read_request<ReqTy>(
        request: Request<Body>,
    ) -> impl Future<Item = Result<(request::Parts, ReqTy), Response<Body>>, Error = failure::Error>
    where ReqTy: for<'de> Deserialize<'de> {
        let (request_parts, request_body) = request.into_parts();

        let request_data = request_body.concat2().from_err();
        let response = request_data.and_then(|data: Chunk| match serde_json::from_slice(&data) {
            Ok(deserialized) => future::Either::A(Ok(Ok((request_parts, deserialized))).into_future()),
            Err(deserialize_error) => {
                let mut response = Response::new(Body::from(deserialize_error.to_string()));
                *response.status_mut() = StatusCode::BAD_REQUEST;
                future::Either::B(Ok(Err(response)).into_future())
            }
        });
        response
    }

    fn handle_result<ResTy>(
        handler_result: Result<Result<ResTy, Response<Body>>, failure::Error>,
    ) -> Result<Response<Body>, failure::Error>
    where ResTy: Serialize + 'static {
        match handler_result {
            Ok(Ok(ok_response)) => {
                let response_data = serde_json::to_vec(&ok_response)?;
                let mut response = Response::builder();
                if let Some(headers) = response.headers_mut() {
                    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
                }
                Ok(response.body(Body::from(response_data))?)
            }
            Ok(Err(err_response)) => Ok(err_response),
            Err(error) => {
                error!("error during request processing: {}", error);

                let mut response = Response::default();
                *response.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
                Ok(response)
            }
        }
    }
}

impl<BackupManagerTy> hyper::service::Service for SignalApiService<BackupManagerTy>
where BackupManagerTy: Clone
{
    type Error = failure::Error;
    type Future = Box<dyn Future<Item = Response<Self::ResBody>, Error = Self::Error> + Send>;
    type ReqBody = Body;
    type ResBody = Body;

    fn call(&mut self, request: Request<Body>) -> Self::Future {
        match self.router.recognize(request.uri().path()) {
            Ok(matched) => {
                let response = matched.handler.handle(self, matched.params, request);

                let logged_response = response.then(|result: Result<Response<Self::ResBody>, Self::Error>| {
                    match &result {
                        Ok(response) => {
                            if response.status().is_client_error() {
                                HTTP_4XX_METER.mark();
                            } else if response.status().is_server_error() {
                                HTTP_5XX_METER.mark();
                            } else {
                                HTTP_OK_METER.mark();
                            }
                        }
                        Err(_error) => {
                            HANDLER_ERROR_METER.mark();
                        }
                    }
                    result.into_future()
                });
                Box::new(logged_response)
            }
            Err(_) => {
                HTTP_4XX_METER.mark();
                let mut response = Response::default();
                *response.status_mut() = StatusCode::NOT_FOUND;
                Box::new(Ok(response).into_future())
            }
        }
    }
}

trait ApiHandler: Send {
    type ApiService;
    fn handle(
        &self,
        service: &Self::ApiService,
        params: route_recognizer::Params,
        request: Request<Body>,
    ) -> Box<dyn Future<Item = Response<Body>, Error = failure::Error> + Send>;
    fn clone_box(&self) -> Box<dyn ApiHandler<ApiService = Self::ApiService>>;
}

impl<ApiServiceTy> Clone for Box<dyn ApiHandler<ApiService = ApiServiceTy>> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}

struct SignalApiHandler<F, ApiServiceTy>(F, std::marker::PhantomData<ApiServiceTy>);

impl<F, ApiServiceTy> SignalApiHandler<F, ApiServiceTy> {
    pub fn new(handler: F) -> Self {
        Self(handler, std::marker::PhantomData)
    }
}

impl<F, FRes, ApiServiceTy> ApiHandler for SignalApiHandler<F, ApiServiceTy>
where
    F: Fn(&ApiServiceTy, route_recognizer::Params, Request<Body>) -> FRes + Send + Clone + 'static,
    FRes: Future<Item = Response<Body>, Error = failure::Error> + Send + 'static,
    ApiServiceTy: Send + 'static,
{
    type ApiService = ApiServiceTy;

    fn handle(
        &self,
        service: &ApiServiceTy,
        params: route_recognizer::Params,
        request: Request<Body>,
    ) -> Box<dyn Future<Item = Response<Body>, Error = failure::Error> + Send>
    {
        Box::new(self.0(service, params, request))
    }

    fn clone_box(&self) -> Box<dyn ApiHandler<ApiService = ApiServiceTy>> {
        Box::new(SignalApiHandler(self.0.clone(), std::marker::PhantomData))
    }
}

#[cfg(test)]
mod test {
    use futures::future;
    use futures::prelude::*;
    use mockers::matchers::*;
    use mockers::Scenario;
    use tokio::runtime::current_thread;

    use super::super::auth::signal_user::test::MockSignalUserToken;
    use super::super::BackupManagerMock;
    use super::*;
    use crate::limits::leaky_bucket::LeakyBucketParameters;

    struct SignalApiServiceTestBuilder {
        ratelimiter_size: u64,
        deny_backup:      bool,
    }

    struct SignalApiServiceTest {
        scenario:       Scenario,
        runtime:        current_thread::Runtime,
        service:        SignalApiService<actor::Sender<BackupManagerMock<SignalUser>>>,
        backup_manager: BackupManagerMockHandle<SignalUser>,
        valid_user:     MockSignalUserToken,
    }

    impl BackupManager for actor::Sender<BackupManagerMock<SignalUser>> {
        type User = SignalUser;

        fn get_token(
            &self,
            enclave_name: String,
            user: &Self::User,
        ) -> Box<dyn Future<Item = GetTokenResponse, Error = EnclaveTransactionError> + Send>
        {
            let user = user.clone();
            let call_result =
                self.sync_call(move |backup_manager: &mut BackupManagerMock<SignalUser>| Ok(backup_manager.get_token(enclave_name, &user)));
            Box::new(call_result.then(|result: Result<_, futures::Canceled>| result.unwrap()))
        }

        fn get_attestation(
            &self,
            enclave_name: String,
            user: &Self::User,
            request: RemoteAttestationRequest,
        ) -> Box<dyn Future<Item = RemoteAttestationResponse, Error = RemoteAttestationError> + Send>
        {
            let user = user.clone();
            let call_result = self.sync_call(move |backup_manager: &mut BackupManagerMock<SignalUser>| {
                Ok(backup_manager.get_attestation(enclave_name, &user, request))
            });
            Box::new(call_result.then(|result: Result<_, futures::Canceled>| result.unwrap()))
        }

        fn put_backup_request(
            &self,
            enclave_name: String,
            user: &Self::User,
            request: KeyBackupRequest,
        ) -> Box<dyn Future<Item = KeyBackupResponse, Error = KeyBackupError> + Send>
        {
            let user = user.clone();
            let call_result = self.sync_call(move |backup_manager: &mut BackupManagerMock<SignalUser>| {
                Ok(backup_manager.put_backup_request(enclave_name, &user, request))
            });
            Box::new(call_result.then(|result: Result<_, futures::Canceled>| result.unwrap()))
        }

        fn delete_backups(&self, user: &Self::User) -> Box<dyn Future<Item = (), Error = EnclaveTransactionError> + Send> {
            let user = user.clone();
            let call_result =
                self.sync_call(move |backup_manager: &mut BackupManagerMock<SignalUser>| Ok(backup_manager.delete_backups(&user)));
            Box::new(call_result.then(|result: Result<_, futures::Canceled>| result.unwrap()))
        }
    }

    impl SignalApiServiceTestBuilder {
        pub fn ratelimiter_size(self, ratelimiter_size: u64) -> Self {
            Self { ratelimiter_size, ..self }
        }

        pub fn deny_backup(self, deny_backup: bool) -> Self {
            Self { deny_backup, ..self }
        }

        pub fn build(self) -> SignalApiServiceTest {
            let scenario = Scenario::new();
            let mut runtime = current_thread::Runtime::new().unwrap();

            let runtime_handle = runtime.handle();

            let (backup_manager_mock, backup_manager) = scenario.create_mock_for();
            let (backup_manager_tx, backup_manager_future) = actor::new(backup_manager_mock);

            let backup_manager_future: Box<dyn Future<Item = (), Error = ()> + 'static> = Box::new(backup_manager_future);
            runtime.spawn(backup_manager_future);

            let hmac_secret = mocks::rand_array();
            let valid_user = MockSignalUserToken::new(hmac_secret, "valid_user".to_string());
            let authenticator = SignalUserAuthenticator::new(&hmac_secret);
            let rate_limiters = SignalApiRateLimiters {
                token:       actor::spawn(
                    RateLimiter::new("token", LeakyBucketParameters {
                        size:      self.ratelimiter_size,
                        leak_rate: self.ratelimiter_size as f64,
                    }),
                    &runtime_handle,
                )
                .unwrap(),
                attestation: actor::spawn(
                    RateLimiter::new("attestation", LeakyBucketParameters {
                        size:      self.ratelimiter_size,
                        leak_rate: self.ratelimiter_size as f64,
                    }),
                    &runtime_handle,
                )
                .unwrap(),
                backup:      actor::spawn(
                    RateLimiter::new("backup", LeakyBucketParameters {
                        size:      self.ratelimiter_size,
                        leak_rate: self.ratelimiter_size as f64,
                    }),
                    &runtime_handle,
                )
                .unwrap(),
            };
            let service = SignalApiService::new(Arc::new(authenticator), backup_manager_tx, self.deny_backup, rate_limiters);
            SignalApiServiceTest {
                scenario,
                runtime,
                service,
                backup_manager,
                valid_user,
            }
        }
    }

    impl SignalApiServiceTest {
        pub fn builder() -> SignalApiServiceTestBuilder {
            SignalApiServiceTestBuilder {
                ratelimiter_size: 10000,
                deny_backup:      false,
            }
        }

        pub fn serve(&self, incoming: mocks::AsyncPipeIncoming) -> impl Future<Item = (), Error = ()> {
            let protocol = hyper::server::conn::Http::new();
            let hyper = hyper::server::Builder::new(incoming, protocol);
            let hyper = hyper.http1_only(true);
            let service = self.service.clone();
            let server = hyper.serve(move || {
                let service: Result<_, failure::Error> = Ok(service.clone());
                service
            });
            server.map_err(|error: hyper::Error| panic!("hyper server error: {}", error))
        }

        fn client(&mut self) -> hyper::Client<mocks::AsyncPipeConnector> {
            let (connector, incoming) = mocks::AsyncPipeConnector::new();
            let client = hyper::client::Builder::default();

            self.runtime.spawn(self.serve(incoming));
            client.build(connector)
        }
    }

    fn valid_remote_attestation_request() -> RemoteAttestationRequest {
        RemoteAttestationRequest {
            clientPublic: mocks::rand_array(),
        }
    }

    fn valid_key_backup_request(request_type: KeyBackupRequestType) -> KeyBackupRequest {
        KeyBackupRequest {
            requestId: mocks::rand_bytes(vec![0; 50]),
            iv:        mocks::rand_array(),
            data:      mocks::rand_bytes(vec![0; 50]),
            mac:       mocks::rand_array(),
            r#type:    request_type,
        }
    }

    #[test]
    fn test_not_found() {
        let mut test = SignalApiServiceTest::builder().build();
        let request = Request::get("http://invalid/nonexistant")
            .header(
                header::AUTHORIZATION,
                mocks::basic_auth(&test.valid_user.username, &test.valid_user),
            )
            .body(Body::empty())
            .unwrap();

        let client = test.client();
        let response = test.runtime.block_on(client.request(request)).unwrap();
        assert_eq!(response.status(), http::StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_get_token_no_authorization() {
        let mut test = SignalApiServiceTest::builder().build();
        let request = Request::get("http://invalid/v1/token/test_enclave").body(Body::empty()).unwrap();

        let client = test.client();
        let response = test.runtime.block_on(client.request(request)).unwrap();
        assert_eq!(response.status(), http::StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_get_token_bad_authorization() {
        let mut test = SignalApiServiceTest::builder().build();
        let request = Request::get("http://invalid/v1/token/test_enclave")
            .header(header::AUTHORIZATION, "zzzz")
            .body(Body::empty())
            .unwrap();

        let client = test.client();
        let response = test.runtime.block_on(client.request(request)).unwrap();
        assert_eq!(response.status(), http::StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_get_token_unauthorized() {
        let mut test = SignalApiServiceTest::builder().build();
        let request = Request::get("http://invalid/v1/token/test_enclave")
            .header(
                header::AUTHORIZATION,
                mocks::basic_auth(&test.valid_user.username, "invalid_password"),
            )
            .body(Body::empty())
            .unwrap();

        let client = test.client();
        let response = test.runtime.block_on(client.request(request)).unwrap();
        assert_eq!(response.status(), http::StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_get_token_ratelimit_exceeded() {
        let mut test = SignalApiServiceTest::builder().ratelimiter_size(0).build();

        test.scenario.expect(
            test.backup_manager
                .get_token("test_enclave".to_string(), ANY)
                .and_return(Box::new(future::lazy(|| -> Result<_, _> { panic!("response future was polled") }))),
        );

        let request = Request::get("http://invalid/v1/token/test_enclave")
            .header(
                header::AUTHORIZATION,
                mocks::basic_auth(&test.valid_user.username, &test.valid_user),
            )
            .body(Body::empty())
            .unwrap();

        let client = test.client();
        let response = test.runtime.block_on(client.request(request)).unwrap();
        assert_eq!(response.status(), http::StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn test_get_token_valid() {
        let mut test = SignalApiServiceTest::builder().build();

        let mock_response = GetTokenResponse {
            backupId: mocks::rand_array::<[u8; 32]>().into(),
            token:    mocks::rand_array(),
            tries:    mocks::rand(),
        };
        test.scenario.expect(
            test.backup_manager
                .get_token("test_enclave".to_string(), ANY)
                .and_return(Box::new(Ok(mock_response.clone()).into_future())),
        );

        let request = Request::get("http://invalid/v1/token/test_enclave")
            .header(
                header::AUTHORIZATION,
                mocks::basic_auth(&test.valid_user.username, &test.valid_user),
            )
            .body(Body::empty())
            .unwrap();

        let client = test.client();
        let response_data = test
            .runtime
            .block_on(
                client
                    .request(request)
                    .and_then(|response: Response<Body>| response.into_body().concat2().from_err()),
            )
            .unwrap();
        let response: GetTokenResponse = serde_json::from_slice(&response_data).unwrap();
        assert_eq!(mock_response, response)
    }

    #[test]
    fn test_get_attestation_bad_method() {
        let mut test = SignalApiServiceTest::builder().build();
        let request = Request::get("http://invalid/v1/attestation/test_enclave")
            .header(
                header::AUTHORIZATION,
                mocks::basic_auth(&test.valid_user.username, &test.valid_user),
            )
            .body(Body::from(serde_json::to_string(&valid_remote_attestation_request()).unwrap()))
            .unwrap();

        let client = test.client();
        let response = test.runtime.block_on(client.request(request)).unwrap();
        assert_eq!(response.status(), http::StatusCode::METHOD_NOT_ALLOWED);
    }

    #[test]
    fn test_get_attestation_no_authorization() {
        let mut test = SignalApiServiceTest::builder().build();
        let request = Request::put("http://invalid/v1/attestation/test_enclave")
            .body(Body::from(serde_json::to_string(&valid_remote_attestation_request()).unwrap()))
            .unwrap();

        let client = test.client();
        let response = test.runtime.block_on(client.request(request)).unwrap();
        assert_eq!(response.status(), http::StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_get_attestation_bad_authorization() {
        let mut test = SignalApiServiceTest::builder().build();
        let request = Request::put("http://invalid/v1/attestation/test_enclave")
            .header(header::AUTHORIZATION, "zzzz")
            .body(Body::from(serde_json::to_string(&valid_remote_attestation_request()).unwrap()))
            .unwrap();

        let client = test.client();
        let response = test.runtime.block_on(client.request(request)).unwrap();
        assert_eq!(response.status(), http::StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_get_attestation_unauthorized() {
        let mut test = SignalApiServiceTest::builder().build();
        let request = Request::put("http://invalid/v1/attestation/test_enclave")
            .header(
                header::AUTHORIZATION,
                mocks::basic_auth(&test.valid_user.username, "invalid_password"),
            )
            .body(Body::from(serde_json::to_string(&valid_remote_attestation_request()).unwrap()))
            .unwrap();

        let client = test.client();
        let response = test.runtime.block_on(client.request(request)).unwrap();
        assert_eq!(response.status(), http::StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_get_attestation_ratelimit_exceeded() {
        let mut test = SignalApiServiceTest::builder().ratelimiter_size(0).build();

        test.scenario.expect(
            test.backup_manager
                .get_attestation("test_enclave".to_string(), ANY, ANY)
                .and_return(Box::new(future::lazy(|| -> Result<_, _> { panic!("response future was polled") }))),
        );

        let request = Request::put("http://invalid/v1/attestation/test_enclave")
            .header(
                header::AUTHORIZATION,
                mocks::basic_auth(&test.valid_user.username, &test.valid_user),
            )
            .body(Body::from(serde_json::to_string(&valid_remote_attestation_request()).unwrap()))
            .unwrap();

        let client = test.client();
        let response = test.runtime.block_on(client.request(request)).unwrap();
        assert_eq!(response.status(), http::StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn test_get_attestation_empty() {
        let mut test = SignalApiServiceTest::builder().build();

        let request = Request::put("http://invalid/v1/attestation/test_enclave")
            .header(
                header::AUTHORIZATION,
                mocks::basic_auth(&test.valid_user.username, &test.valid_user),
            )
            .body(Body::empty())
            .unwrap();

        let client = test.client();
        let response = test.runtime.block_on(client.request(request)).unwrap();
        assert_eq!(response.status(), http::StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_get_attestation_invalid_input() {
        let mut test = SignalApiServiceTest::builder().build();

        let mock_error = RemoteAttestationError::InvalidInput;
        test.scenario.expect(
            test.backup_manager
                .get_attestation("test_enclave".to_string(), ANY, ANY)
                .and_return(Box::new(Err(mock_error).into_future())),
        );

        let request = Request::put("http://invalid/v1/attestation/test_enclave")
            .header(
                header::AUTHORIZATION,
                mocks::basic_auth(&test.valid_user.username, &test.valid_user),
            )
            .body(Body::from(serde_json::to_string(&valid_remote_attestation_request()).unwrap()))
            .unwrap();

        let client = test.client();
        let response = test.runtime.block_on(client.request(request)).unwrap();
        assert_eq!(response.status(), http::StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_get_attestation_valid() {
        let mut test = SignalApiServiceTest::builder().build();

        let mock_response = RemoteAttestationResponse {
            serverEphemeralPublic: mocks::rand_array(),
            serverStaticPublic:    mocks::rand_array(),
            quote:                 mocks::rand_bytes(vec![0; 100]),
            iv:                    mocks::rand_array(),
            ciphertext:            mocks::rand_bytes(vec![0; 50]),
            tag:                   mocks::rand_array(),
            signature:             mocks::rand_bytes(vec![0; 64]),
            certificates:          "test_certificates".to_string(),
            signatureBody:         "test_signature_body".to_string(),
        };
        test.scenario.expect(
            test.backup_manager
                .get_attestation("test_enclave".to_string(), ANY, ANY)
                .and_return(Box::new(Ok(mock_response.clone()).into_future())),
        );

        let request = Request::put("http://invalid/v1/attestation/test_enclave")
            .header(
                header::AUTHORIZATION,
                mocks::basic_auth(&test.valid_user.username, &test.valid_user),
            )
            .body(Body::from(serde_json::to_string(&valid_remote_attestation_request()).unwrap()))
            .unwrap();

        let client = test.client();
        let response_data = test
            .runtime
            .block_on(client.request(request).and_then(|response: Response<Body>| {
                assert!(response.status().is_success());
                response.into_body().concat2().from_err()
            }))
            .unwrap();
        let response: RemoteAttestationResponse = serde_json::from_slice(&response_data).unwrap();
        assert_eq!(mock_response, response)
    }

    #[test]
    fn test_put_backup_request_bad_method() {
        let mut test = SignalApiServiceTest::builder().build();
        let request = Request::get("http://invalid/v1/backup/test_enclave")
            .header(
                header::AUTHORIZATION,
                mocks::basic_auth(&test.valid_user.username, &test.valid_user),
            )
            .body(Body::from(
                serde_json::to_string(&valid_key_backup_request(KeyBackupRequestType::Backup)).unwrap(),
            ))
            .unwrap();

        let client = test.client();
        let response = test.runtime.block_on(client.request(request)).unwrap();
        assert_eq!(response.status(), http::StatusCode::METHOD_NOT_ALLOWED);
    }

    #[test]
    fn test_put_backup_request_no_authorization() {
        let mut test = SignalApiServiceTest::builder().build();
        let request = Request::put("http://invalid/v1/backup/test_enclave")
            .body(Body::from(
                serde_json::to_string(&valid_key_backup_request(KeyBackupRequestType::Backup)).unwrap(),
            ))
            .unwrap();

        let client = test.client();
        let response = test.runtime.block_on(client.request(request)).unwrap();
        assert_eq!(response.status(), http::StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_put_backup_request_bad_authorization() {
        let mut test = SignalApiServiceTest::builder().build();
        let request = Request::put("http://invalid/v1/backup/test_enclave")
            .header(header::AUTHORIZATION, "zzzz")
            .body(Body::from(
                serde_json::to_string(&valid_key_backup_request(KeyBackupRequestType::Backup)).unwrap(),
            ))
            .unwrap();

        let client = test.client();
        let response = test.runtime.block_on(client.request(request)).unwrap();
        assert_eq!(response.status(), http::StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_put_backup_request_unauthorized() {
        let mut test = SignalApiServiceTest::builder().build();
        let request = Request::put("http://invalid/v1/backup/test_enclave")
            .header(
                header::AUTHORIZATION,
                mocks::basic_auth(&test.valid_user.username, "invalid_password"),
            )
            .body(Body::from(
                serde_json::to_string(&valid_key_backup_request(KeyBackupRequestType::Backup)).unwrap(),
            ))
            .unwrap();

        let client = test.client();
        let response = test.runtime.block_on(client.request(request)).unwrap();
        assert_eq!(response.status(), http::StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_put_backup_request_ratelimit_exceeded() {
        let mut test = SignalApiServiceTest::builder().ratelimiter_size(0).build();

        test.scenario.expect(
            test.backup_manager
                .put_backup_request("test_enclave".to_string(), ANY, ANY)
                .and_return(Box::new(future::lazy(|| -> Result<_, _> { panic!("response future was polled") }))),
        );

        let request = Request::put("http://invalid/v1/backup/test_enclave")
            .header(
                header::AUTHORIZATION,
                mocks::basic_auth(&test.valid_user.username, &test.valid_user),
            )
            .body(Body::from(
                serde_json::to_string(&valid_key_backup_request(KeyBackupRequestType::Backup)).unwrap(),
            ))
            .unwrap();

        let client = test.client();
        let response = test.runtime.block_on(client.request(request)).unwrap();
        assert_eq!(response.status(), http::StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn test_put_backup_request_empty() {
        let mut test = SignalApiServiceTest::builder().build();
        let request = Request::put("http://invalid/v1/backup/test_enclave")
            .header(
                header::AUTHORIZATION,
                mocks::basic_auth(&test.valid_user.username, &test.valid_user),
            )
            .body(Body::empty())
            .unwrap();

        let client = test.client();
        let response = test.runtime.block_on(client.request(request)).unwrap();
        assert_eq!(response.status(), http::StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_put_backup_request_invalid_input() {
        let mut test = SignalApiServiceTest::builder().build();

        let mock_error = KeyBackupError::InvalidInput;
        test.scenario.expect(
            test.backup_manager
                .put_backup_request("test_enclave".to_string(), ANY, ANY)
                .and_return(Box::new(Err(mock_error).into_future())),
        );

        let request = Request::put("http://invalid/v1/backup/test_enclave")
            .header(
                header::AUTHORIZATION,
                mocks::basic_auth(&test.valid_user.username, &test.valid_user),
            )
            .body(Body::from(
                serde_json::to_string(&valid_key_backup_request(KeyBackupRequestType::Backup)).unwrap(),
            ))
            .unwrap();

        let client = test.client();
        let response = test.runtime.block_on(client.request(request)).unwrap();
        assert_eq!(response.status(), http::StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_put_backup_request_mac_mismatch() {
        let mut test = SignalApiServiceTest::builder().build();

        let mock_error = KeyBackupError::MacMismatch;
        test.scenario.expect(
            test.backup_manager
                .put_backup_request("test_enclave".to_string(), ANY, ANY)
                .and_return(Box::new(Err(mock_error).into_future())),
        );

        let request = Request::put("http://invalid/v1/backup/test_enclave")
            .header(
                header::AUTHORIZATION,
                mocks::basic_auth(&test.valid_user.username, &test.valid_user),
            )
            .body(Body::from(
                serde_json::to_string(&valid_key_backup_request(KeyBackupRequestType::Backup)).unwrap(),
            ))
            .unwrap();

        let client = test.client();
        let response = test.runtime.block_on(client.request(request)).unwrap();
        assert_eq!(response.status(), http::StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_put_backup_request_pending_request_id_not_found() {
        let mut test = SignalApiServiceTest::builder().build();

        let mock_error = KeyBackupError::PendingRequestIdNotFound;
        test.scenario.expect(
            test.backup_manager
                .put_backup_request("test_enclave".to_string(), ANY, ANY)
                .and_return(Box::new(Err(mock_error).into_future())),
        );

        let request = Request::put("http://invalid/v1/backup/test_enclave")
            .header(
                header::AUTHORIZATION,
                mocks::basic_auth(&test.valid_user.username, &test.valid_user),
            )
            .body(Body::from(
                serde_json::to_string(&valid_key_backup_request(KeyBackupRequestType::Backup)).unwrap(),
            ))
            .unwrap();

        let client = test.client();
        let response = test.runtime.block_on(client.request(request)).unwrap();
        assert_eq!(response.status(), http::StatusCode::GONE);
    }

    #[test]
    fn test_put_backup_request_valid() {
        let mut test = SignalApiServiceTest::builder().build();

        let mock_response = KeyBackupResponse {
            iv:   mocks::rand_array(),
            data: mocks::rand_bytes(vec![0; 50]),
            mac:  mocks::rand_array(),
        };
        test.scenario.expect(
            test.backup_manager
                .put_backup_request("test_enclave".to_string(), ANY, ANY)
                .and_return(Box::new(Ok(mock_response.clone()).into_future())),
        );

        let request = Request::put("http://invalid/v1/backup/test_enclave")
            .header(
                header::AUTHORIZATION,
                mocks::basic_auth(&test.valid_user.username, &test.valid_user),
            )
            .body(Body::from(
                serde_json::to_string(&valid_key_backup_request(KeyBackupRequestType::Backup)).unwrap(),
            ))
            .unwrap();

        let client = test.client();
        let response_data = test
            .runtime
            .block_on(client.request(request).and_then(|response: Response<Body>| {
                assert!(response.status().is_success());
                response.into_body().concat2().from_err()
            }))
            .unwrap();
        let response: KeyBackupResponse = serde_json::from_slice(&response_data).unwrap();
        assert_eq!(mock_response, response)
    }

    #[test]
    fn test_put_backup_request_deny_backup() {
        let mut test = SignalApiServiceTest::builder().deny_backup(true).build();

        let mock_token_response = GetTokenResponse {
            backupId: mocks::rand_array::<[u8; 32]>().into(),
            token:    mocks::rand_array(),
            tries:    mocks::rand(),
        };
        let mock_backup_response = KeyBackupResponse {
            iv:   mocks::rand_array(),
            data: mocks::rand_bytes(vec![0; 50]),
            mac:  mocks::rand_array(),
        };

        let mock_backup_response_2 = mock_backup_response.clone();
        test.scenario.expect(
            test.backup_manager
                .get_token("test_enclave".to_string(), ANY)
                .and_return(Box::new(Ok(mock_token_response.clone()).into_future())),
        );
        test.scenario.expect(
            test.backup_manager
                .put_backup_request("test_enclave".to_string(), ANY, ANY)
                .and_call_clone(move |_, _, _| Box::new(Ok(mock_backup_response_2.clone()).into_future()))
                .times(2),
        );

        let token_request = Request::get("http://invalid/v1/token/test_enclave")
            .header(
                header::AUTHORIZATION,
                mocks::basic_auth(&test.valid_user.username, &test.valid_user),
            )
            .body(Body::empty())
            .unwrap();
        let backup_request = Request::put("http://invalid/v1/backup/test_enclave")
            .header(
                header::AUTHORIZATION,
                mocks::basic_auth(&test.valid_user.username, &test.valid_user),
            )
            .body(Body::from(
                serde_json::to_string(&valid_key_backup_request(KeyBackupRequestType::Backup)).unwrap(),
            ))
            .unwrap();
        let restore_request = Request::put("http://invalid/v1/backup/test_enclave")
            .header(
                header::AUTHORIZATION,
                mocks::basic_auth(&test.valid_user.username, &test.valid_user),
            )
            .body(Body::from(
                serde_json::to_string(&valid_key_backup_request(KeyBackupRequestType::Restore)).unwrap(),
            ))
            .unwrap();
        let delete_request = Request::put("http://invalid/v1/backup/test_enclave")
            .header(
                header::AUTHORIZATION,
                mocks::basic_auth(&test.valid_user.username, &test.valid_user),
            )
            .body(Body::from(
                serde_json::to_string(&valid_key_backup_request(KeyBackupRequestType::Delete)).unwrap(),
            ))
            .unwrap();

        let client = test.client();
        test.runtime
            .block_on(client.request(backup_request).map(|response: Response<Body>| {
                assert!(response.status().is_server_error());
            }))
            .unwrap();

        let response_data = test
            .runtime
            .block_on(client.request(restore_request).and_then(|response: Response<Body>| {
                assert!(response.status().is_success());
                response.into_body().concat2().from_err()
            }))
            .unwrap();
        assert_eq!(mock_backup_response, serde_json::from_slice(&response_data).unwrap());

        let response_data = test
            .runtime
            .block_on(client.request(delete_request).and_then(|response: Response<Body>| {
                assert!(response.status().is_success());
                response.into_body().concat2().from_err()
            }))
            .unwrap();
        assert_eq!(mock_backup_response, serde_json::from_slice(&response_data).unwrap());

        let response_data = test
            .runtime
            .block_on(
                client
                    .request(token_request)
                    .and_then(|response: Response<Body>| response.into_body().concat2().from_err()),
            )
            .unwrap();
        assert_eq!(mock_token_response, serde_json::from_slice(&response_data).unwrap());
    }

    #[test]
    fn test_delete_backups_request_bad_method() {
        let mut test = SignalApiServiceTest::builder().build();
        let request = Request::get("http://invalid/v1/backup")
            .header(
                header::AUTHORIZATION,
                mocks::basic_auth(&test.valid_user.username, &test.valid_user),
            )
            .body(Body::empty())
            .unwrap();

        let client = test.client();
        let response = test.runtime.block_on(client.request(request)).unwrap();
        assert_eq!(response.status(), http::StatusCode::METHOD_NOT_ALLOWED);
    }

    #[test]
    fn test_delete_backups_request_no_authorization() {
        let mut test = SignalApiServiceTest::builder().build();
        let request = Request::delete("http://invalid/v1/backup").body(Body::empty()).unwrap();

        let client = test.client();
        let response = test.runtime.block_on(client.request(request)).unwrap();
        assert_eq!(response.status(), http::StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_delete_backups_request_bad_authorization() {
        let mut test = SignalApiServiceTest::builder().build();
        let request = Request::delete("http://invalid/v1/backup")
            .header(header::AUTHORIZATION, "zzzz")
            .body(Body::empty())
            .unwrap();

        let client = test.client();
        let response = test.runtime.block_on(client.request(request)).unwrap();
        assert_eq!(response.status(), http::StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_delete_backups_request_unauthorized() {
        let mut test = SignalApiServiceTest::builder().build();
        let request = Request::delete("http://invalid/v1/backup")
            .header(
                header::AUTHORIZATION,
                mocks::basic_auth(&test.valid_user.username, "invalid_password"),
            )
            .body(Body::empty())
            .unwrap();

        let client = test.client();
        let response = test.runtime.block_on(client.request(request)).unwrap();
        assert_eq!(response.status(), http::StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_delete_backups_request_ratelimit_exceeded() {
        let mut test = SignalApiServiceTest::builder().ratelimiter_size(0).build();

        test.scenario.expect(
            test.backup_manager
                .delete_backups(ANY)
                .and_return(Box::new(future::lazy(|| -> Result<_, _> { panic!("response future was polled") }))),
        );

        let request = Request::delete("http://invalid/v1/backup")
            .header(
                header::AUTHORIZATION,
                mocks::basic_auth(&test.valid_user.username, &test.valid_user),
            )
            .body(Body::empty())
            .unwrap();

        let client = test.client();
        let response = test.runtime.block_on(client.request(request)).unwrap();
        assert_eq!(response.status(), http::StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn test_delete_backups_request_valid() {
        let mut test = SignalApiServiceTest::builder().build();

        test.scenario
            .expect(test.backup_manager.delete_backups(ANY).and_return(Box::new(Ok(()).into_future())));

        let request = Request::delete("http://invalid/v1/backup")
            .header(
                header::AUTHORIZATION,
                mocks::basic_auth(&test.valid_user.username, &test.valid_user),
            )
            .body(Body::empty())
            .unwrap();

        let client = test.client();
        test.runtime
            .block_on(client.request(request).and_then(|response: Response<Body>| {
                assert!(response.status().is_success());
                response.into_body().concat2().from_err()
            }))
            .unwrap();
    }
}
