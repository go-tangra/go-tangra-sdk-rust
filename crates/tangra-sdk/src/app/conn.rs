//! A late-bound gRPC connection to a platform service (`gateway`, `auth`).
//!
//! Go modules hold the `*grpc.ClientConn` from `freya.App.Client`. Here a
//! [`ServiceConn`] asks the app's pool for the channel on every call, so a
//! trust-bundle rotation (which drains the pool) is picked up; tests can
//! pass a plain tonic `Channel` instead.

use std::sync::Arc;

use http::{Request, Response};
use tower::util::BoxCloneSyncService;

use super::{App, ClientError};

/// A type-erased gRPC channel accepted by every tonic-generated client.
pub type GrpcChannel =
    BoxCloneSyncService<Request<tonic::body::Body>, Response<tonic::body::Body>, tonic::transport::Error>;

type Dial = dyn Fn() -> Result<GrpcChannel, ClientError> + Send + Sync;

/// Where calls to a platform service go.
#[derive(Clone)]
pub struct ServiceConn {
    dial: Arc<Dial>,
    name: String,
}

impl std::fmt::Debug for ServiceConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceConn")
            .field("service", &self.name)
            .finish()
    }
}

impl ServiceConn {
    /// The app's pooled mTLS channel to `service` (resolved per call).
    pub fn app(app: &App, service: &str) -> Self {
        let app = app.clone();
        let svc = service.to_owned();
        Self {
            name: service.to_owned(),
            dial: Arc::new(move || {
                let ch = app.client(&svc)?;
                Ok(BoxCloneSyncService::new(ch))
            }),
        }
    }

    /// A fixed tonic channel (tests, custom transports).
    pub fn channel(ch: tonic::transport::Channel) -> Self {
        Self {
            name: "channel".into(),
            dial: Arc::new(move || Ok(BoxCloneSyncService::new(ch.clone()))),
        }
    }

    /// The service name (or `channel`).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The channel for one call.
    pub fn get(&self) -> Result<GrpcChannel, ClientError> {
        (self.dial)()
    }
}
