//! [`PathValidator`](crate::api::PathValidator) implementations

#[cfg(feature = "openssl")]
pub mod openssl;

pub mod default;
