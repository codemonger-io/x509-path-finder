use crate::certificate::Certificate;
use std::sync::Arc;
#[cfg(feature = "resolve")]
use url::Url;
use x509_path_finder_material::generate::CertificatePathGenerator;

#[test]
fn test_issuers() {
    let certificates = CertificatePathGenerator::generate(2, "issuers")
        .unwrap()
        .into_iter()
        .map(|c| Arc::new(c).into())
        .collect::<Vec<Certificate>>();

    assert!(certificates[1].issued(&certificates[0]));
}

#[cfg(feature = "resolve")]
#[test]
fn test_aia() {
    let certificates = CertificatePathGenerator::generate(2, "aia")
        .unwrap()
        .into_iter()
        .map(|c| Arc::new(c).into())
        .collect::<Vec<Certificate>>();

    assert_eq!(
        vec![Url::parse("test://aia").unwrap(),],
        certificates[0].aia()
    )
}
