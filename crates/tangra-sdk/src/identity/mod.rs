//! Service identity: SPIFFE IDs.

mod spiffeid;

pub use spiffeid::{SpiffeId, SpiffeIdError, valid_service_name, valid_trust_domain};
