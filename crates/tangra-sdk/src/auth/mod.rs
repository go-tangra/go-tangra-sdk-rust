//! End-user authentication and auth registration (auth
//! `sdk/pkg/authclient`, tag `sdk/v4.3.0` — the version the deployer pins).
//!
//! The gateway forwards the platform access token as `Authorization:
//! Bearer`; the module verifies it offline:
//!
//! - [`Verifier`] checks EdDSA tokens ([`verify_token`]) against keys from
//!   `auth.v1.Keys/List` ([`GrpcKeys`], refreshed every 5 minutes and at
//!   most once a minute on an unknown `kid`) or a JWKS URL ([`HttpKeys`]),
//!   and applies the revocation feed `auth.v1.Sessions/RevokedSince`
//!   ([`GrpcRevocations`], polled every 5s), failing closed once the feed is
//!   60 minutes stale.
//! - [`UserAuthLayer`] / [`User`] put it on axum routes; [`verify_grpc`] on
//!   tonic handlers.
//! - [`Registration`] registers permissions, module roles and built-in
//!   grants with `auth.v1.Authorization/RegisterPermissions`;
//!   [`registration_loop`] is the deployer's 5s-retry / 5-minute refresh.
//! - [`AuthzClient`] calls `Authorization/Check|BatchCheck` and
//!   `Profiles/ListMembers`.
//!
//! With an [`App`](crate::app::App), use
//! [`App::user_auth`](crate::app::App::user_auth) and
//! [`App::auth_registration`](crate::app::App::auth_registration).

mod check;
mod grpc;
mod jwks;
mod middleware;
mod registration;
mod signer;
mod token;
mod verifier;

pub use check::{AuthzClient, CALL_TIMEOUT, MAX_MEMBERS, MEMBERS_PAGE};
pub use grpc::{GrpcKeys, GrpcRevocations};
pub use jwks::{HttpKeys, Jwk, Jwks, MAX_JWKS_BYTES, parse_jwks};
pub use middleware::{
    Unauthenticated, UserAuth, UserAuthLayer, bearer_from_headers, bearer_token, unauthenticated, verify_grpc,
};
pub use registration::{
    BUILTIN_ROLES, InvalidRegistration, MAX_PERMISSIONS, MAX_ROLE_PERMISSIONS, MAX_ROLES, ModuleRole,
    Permission, REGISTER_PERIOD, REGISTER_RETRY, REGISTER_TIMEOUT, Registration, registration_loop,
};
pub use signer::TestSigner;
pub use token::{Claims, MAX_SKEW, MAX_TOKEN_BYTES, MAX_TOKEN_LIFETIME, TokenError, verify_token};
pub use verifier::{
    AuthError, Config, Identity, KeySource, OnError, PublicKey, Revocation, RevocationSource, StaticKeys,
    User, Verifier, VerifyError,
};

#[cfg(test)]
mod tests;
