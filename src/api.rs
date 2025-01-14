//! API Traits

use std::fmt::{Debug, Display};

/// Certificate path validation. Implement to customize behavior. Note: X509 certificate [path validation](https://datatracker.ietf.org/doc/html/rfc5280#section-6) is not
/// trivial. Implement to add business logic, but leverage a trusted X509 validator within.
pub trait PathValidator {
    /// Error type
    type PathValidatorError: PathValidatorError;

    /// Validates `path`, returning results as [`CertificatePathValidation`](crate::api::CertificatePathValidation)
    fn validate(
        &self,
        path: Vec<&crate::Certificate>,
    ) -> Result<CertificatePathValidation, Self::PathValidatorError>;
}

/// Result of [`validate`](crate::api::PathValidator::validate)
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum CertificatePathValidation {
    /// Valid path found
    ///
    /// The parameter is a DER representation of the trust anchor.
    Found(Vec<u8>),
    /// Valid path not found
    NotFound(String),
}

/// Error trait
pub trait PathValidatorError: Display + Debug {}
