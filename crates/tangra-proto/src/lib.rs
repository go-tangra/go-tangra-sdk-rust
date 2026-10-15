//! go-tangra v4 platform protos, vendored verbatim (see `SOURCES.md`) and
//! compiled with tonic/prost. Each package exposes its messages plus the
//! generated `*_client` and `*_server` modules.

#![allow(clippy::all, clippy::pedantic, missing_docs)]

/// `gateway.v1` - the application gateway registry (portal).
pub mod gateway {
    /// `gateway.v1`.
    pub mod v1 {
        tonic::include_proto!("gateway.v1");
    }
}

/// `auth.v1` - tokens, keys, sessions, authorization (auth).
pub mod auth {
    /// `auth.v1`.
    pub mod v1 {
        tonic::include_proto!("auth.v1");
    }
}

/// `lcm.v1` - certificate lifecycle and mesh enrollment (lcm).
pub mod lcm {
    /// `lcm.v1`.
    pub mod v1 {
        tonic::include_proto!("lcm.v1");
    }
}
