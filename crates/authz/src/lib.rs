//! Who may use which Garrison module and maintenance action.
//!
//! The root-managed policy names profiles; a user's current native Stalwart
//! permissions are an upper bound on every profile. Only the broker evaluates
//! it; the web service enforces the resulting [`Grant`].

pub mod authority;
pub mod grant;
pub mod policy;

pub use authority::Authority;
pub use garrison_stalwart::Error;
pub use grant::Grant;
pub use policy::Policy;
