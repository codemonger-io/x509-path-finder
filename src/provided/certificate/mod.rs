//! [`Certificate`](crate::api::Certificate) implementations

#[cfg(feature = "openssl")]
pub mod openssl;

pub mod default;
