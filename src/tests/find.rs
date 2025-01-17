use crate::report::CertificateOrigin;
use crate::tests::test_validator::TestPathValidator;
#[cfg(feature = "resolve")]
use crate::TestAIA;
use crate::{X509PathFinder, X509PathFinderConfiguration};
#[cfg(feature = "resolve")]
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
#[cfg(feature = "resolve")]
use url::Url;
use x509_path_finder_material::generate::CertificatePathGenerator;

#[cfg(feature = "resolve")]
#[tokio::test]
async fn test_limit() {
    let mut certificates = CertificatePathGenerator::generate(3, "authority").unwrap();
    let root = certificates.pop().unwrap();
    let ee = certificates.remove(0);

    let validator = TestPathValidator::new(vec![root.clone()]);

    let mut aia = HashMap::new();
    aia.insert(
        Url::parse("test://1.authority").unwrap(),
        Arc::new(certificates[0].clone()),
    );

    let mut search = X509PathFinder::new(X509PathFinderConfiguration {
        limit: Duration::from_millis(500),
        aia: Some(TestAIA {
            certificates: aia.clone(),
            sleep: Some(Duration::from_millis(200)),
        }),
        validator: validator.clone(),
        certificates: vec![ee.clone().into()],
    });

    let report = search.find(ee.clone()).await.unwrap();
    let found = report.found.unwrap();

    assert_eq!(0, report.failures.len());
    assert_eq!(
        vec![Arc::new(ee.clone()), Arc::new(certificates[0].clone())],
        found.path
    );
    assert_eq!(
        vec![
            CertificateOrigin::Target,
            CertificateOrigin::Url(Url::parse("test://1.authority").unwrap()),
        ],
        found.origin
    );

    let mut search = X509PathFinder::new(X509PathFinderConfiguration {
        limit: Duration::from_millis(100),
        aia: Some(TestAIA {
            certificates: aia,
            sleep: Some(Duration::from_millis(200)),
        }),
        validator: validator.clone(),
        certificates: vec![ee.clone().into()],
    });

    assert!(search.find(ee.clone()).await.is_err());
}

#[tokio::test]
async fn test_self_signed() {
    let root = CertificatePathGenerator::generate(1, "0")
        .unwrap()
        .into_iter()
        .next()
        .unwrap();

    let validator = TestPathValidator::new(vec![root.clone()]);

    let mut search = X509PathFinder::new(X509PathFinderConfiguration {
        limit: Duration::default(),
        #[cfg(feature = "resolve")]
        aia: None,
        validator,
        certificates: vec![],
    });

    let report = search.find(root.clone()).await.unwrap();
    let found = report.found.unwrap();

    assert_eq!(0, report.failures.len());
    assert_eq!(vec![Arc::new(root)], found.path);
    assert_eq!(vec![CertificateOrigin::Target,], found.origin);
}

#[test]
fn test_self_signed_sync() {
    let root = CertificatePathGenerator::generate(1, "0")
        .unwrap()
        .into_iter()
        .next()
        .unwrap();

    let validator = TestPathValidator::new(vec![root.clone()]);

    let mut search = X509PathFinder::new(X509PathFinderConfiguration {
        limit: Duration::default(),
        #[cfg(feature = "resolve")]
        aia: None,
        validator,
        certificates: vec![],
    });

    let report = search.find_sync(root.clone()).unwrap();
    let found = report.found.unwrap();

    assert_eq!(0, report.failures.len());
    assert_eq!(vec![Arc::new(root)], found.path);
    assert_eq!(vec![CertificateOrigin::Target,], found.origin);
}

#[tokio::test]
async fn test_direct_path_no_aia() {
    let mut certificates = CertificatePathGenerator::generate(8, "0")
        .unwrap()
        .into_iter()
        .map(|c| Arc::new(c))
        .collect::<Vec<Arc<crate::Certificate>>>();
    let root = certificates.pop().unwrap();
    let expected = certificates.clone();

    let ee = certificates.remove(0);

    let validator = TestPathValidator::new(vec![root.as_ref().clone()]);

    let mut search = X509PathFinder::new(X509PathFinderConfiguration {
        limit: Duration::default(),
        #[cfg(feature = "resolve")]
        aia: None,
        validator,
        certificates,
    });

    let report = search.find(ee).await.unwrap();
    let found = report.found.unwrap();

    assert_eq!(0, report.failures.len());
    assert_eq!(expected, found.path);
    assert_eq!(
        vec![
            CertificateOrigin::Target,
            CertificateOrigin::Store,
            CertificateOrigin::Store,
            CertificateOrigin::Store,
            CertificateOrigin::Store,
            CertificateOrigin::Store,
            CertificateOrigin::Store,
        ],
        found.origin
    );
}

#[test]
fn test_direct_path_no_aia_sync() {
    let mut certificates = CertificatePathGenerator::generate(8, "0")
        .unwrap()
        .into_iter()
        .map(|c| Arc::new(c))
        .collect::<Vec<Arc<crate::Certificate>>>();
    let root = certificates.pop().unwrap();
    let expected = certificates.clone();

    let ee = certificates.remove(0);

    let validator = TestPathValidator::new(vec![root.as_ref().clone()]);

    let mut search = X509PathFinder::new(X509PathFinderConfiguration {
        limit: Duration::default(),
        #[cfg(feature = "resolve")]
        aia: None,
        validator,
        certificates,
    });

    let report = search.find_sync(ee).unwrap();
    let found = report.found.unwrap();

    assert_eq!(0, report.failures.len());
    assert_eq!(expected, found.path);
    assert_eq!(
        vec![
            CertificateOrigin::Target,
            CertificateOrigin::Store,
            CertificateOrigin::Store,
            CertificateOrigin::Store,
            CertificateOrigin::Store,
            CertificateOrigin::Store,
            CertificateOrigin::Store,
        ],
        found.origin
    );
}

#[tokio::test]
async fn test_cross_first_no_aia() {
    let mut authority1_certificates = CertificatePathGenerator::generate(8, "authority1")
        .unwrap()
        .into_iter()
        .map(|c| c.into())
        .collect::<Vec<Arc<crate::Certificate>>>();
    let authority1_root = authority1_certificates.pop().unwrap();
    let authority1_ee = authority1_certificates[0].clone();
    let authority1_ic = authority1_certificates[1].clone();

    let (mut authority2_certificates, mut authority2_keys) =
        CertificatePathGenerator::generate_with_keys(1, "authority2").unwrap();
    let authority2_root = authority2_certificates.pop().unwrap();
    let authority2_root_key = authority2_keys.pop().unwrap();

    let cross =
        CertificatePathGenerator::cross(&authority2_root, &authority2_root_key, &authority1_ic)
            .unwrap();

    let mut cached_certificates_cross_first = vec![Arc::new(cross.clone())];
    cached_certificates_cross_first.extend(authority1_certificates.clone());

    let validator = TestPathValidator::new(vec![
        authority1_root.as_ref().clone(),
        authority2_root.clone(),
    ]);

    let report = X509PathFinder::new(X509PathFinderConfiguration {
        limit: Duration::default(),
        #[cfg(feature = "resolve")]
        aia: None,
        validator,
        certificates: cached_certificates_cross_first,
    })
    .find(authority1_ee.clone())
    .await
    .unwrap();

    let found = report.found.unwrap();

    assert_eq!(0, report.failures.len());
    assert_eq!(vec![authority1_ee.clone(), Arc::new(cross)], found.path);
    assert_eq!(
        vec![CertificateOrigin::Target, CertificateOrigin::Store,],
        found.origin
    );
}

#[test]
fn test_cross_first_no_aia_sync() {
    let mut authority1_certificates = CertificatePathGenerator::generate(8, "authority1")
        .unwrap()
        .into_iter()
        .map(|c| c.into())
        .collect::<Vec<Arc<crate::Certificate>>>();
    let authority1_root = authority1_certificates.pop().unwrap();
    let authority1_ee = authority1_certificates[0].clone();
    let authority1_ic = authority1_certificates[1].clone();

    let (mut authority2_certificates, mut authority2_keys) =
        CertificatePathGenerator::generate_with_keys(1, "authority2").unwrap();
    let authority2_root = authority2_certificates.pop().unwrap();
    let authority2_root_key = authority2_keys.pop().unwrap();

    let cross =
        CertificatePathGenerator::cross(&authority2_root, &authority2_root_key, &authority1_ic)
            .unwrap();

    let mut cached_certificates_cross_first = vec![Arc::new(cross.clone())];
    cached_certificates_cross_first.extend(authority1_certificates.clone());

    let validator = TestPathValidator::new(vec![
        authority1_root.as_ref().clone(),
        authority2_root.clone(),
    ]);

    let report = X509PathFinder::new(X509PathFinderConfiguration {
        limit: Duration::default(),
        #[cfg(feature = "resolve")]
        aia: None,
        validator,
        certificates: cached_certificates_cross_first,
    })
    .find_sync(authority1_ee.clone())
    .unwrap();

    let found = report.found.unwrap();

    assert_eq!(0, report.failures.len());
    assert_eq!(vec![authority1_ee.clone(), Arc::new(cross)], found.path);
    assert_eq!(
        vec![CertificateOrigin::Target, CertificateOrigin::Store,],
        found.origin
    );
}

#[tokio::test]
async fn test_cross_last_no_aia() {
    let mut authority1_certificates = CertificatePathGenerator::generate(8, "authority1")
        .unwrap()
        .into_iter()
        .map(|c| c.into())
        .collect::<Vec<Arc<crate::Certificate>>>();
    let authority1_root = authority1_certificates.pop().unwrap();
    let authority1_ee = authority1_certificates[0].clone();
    let authority1_ic = authority1_certificates[1].clone();

    let (mut authority2_certificates, mut authority2_keys) =
        CertificatePathGenerator::generate_with_keys(1, "authority2").unwrap();
    let authority2_root = authority2_certificates.pop().unwrap();
    let authority2_root_key = authority2_keys.pop().unwrap();

    let cross =
        CertificatePathGenerator::cross(&authority2_root, &authority2_root_key, &authority1_ic)
            .unwrap();

    let mut cached_certificates_cross_last = authority1_certificates.clone();
    cached_certificates_cross_last.push(Arc::new(cross.clone()));

    let validator = TestPathValidator::new(vec![authority1_root.as_ref().clone(), authority2_root]);

    let report = X509PathFinder::new(X509PathFinderConfiguration {
        limit: Duration::default(),
        #[cfg(feature = "resolve")]
        aia: None,
        validator,
        certificates: cached_certificates_cross_last,
    })
    .find(authority1_ee.clone())
    .await
    .unwrap();

    let found = report.found.unwrap();

    assert_eq!(0, report.failures.len());
    assert_eq!(authority1_certificates, found.path);
    assert_eq!(
        vec![
            CertificateOrigin::Target,
            CertificateOrigin::Store,
            CertificateOrigin::Store,
            CertificateOrigin::Store,
            CertificateOrigin::Store,
            CertificateOrigin::Store,
            CertificateOrigin::Store
        ],
        found.origin
    );
}

#[test]
fn test_cross_last_no_aia_sync() {
    let mut authority1_certificates = CertificatePathGenerator::generate(8, "authority1")
        .unwrap()
        .into_iter()
        .map(|c| c.into())
        .collect::<Vec<Arc<crate::Certificate>>>();
    let authority1_root = authority1_certificates.pop().unwrap();
    let authority1_ee = authority1_certificates[0].clone();
    let authority1_ic = authority1_certificates[1].clone();

    let (mut authority2_certificates, mut authority2_keys) =
        CertificatePathGenerator::generate_with_keys(1, "authority2").unwrap();
    let authority2_root = authority2_certificates.pop().unwrap();
    let authority2_root_key = authority2_keys.pop().unwrap();

    let cross =
        CertificatePathGenerator::cross(&authority2_root, &authority2_root_key, &authority1_ic)
            .unwrap();

    let mut cached_certificates_cross_last = authority1_certificates.clone();
    cached_certificates_cross_last.push(Arc::new(cross.clone()));

    let validator = TestPathValidator::new(vec![authority1_root.as_ref().clone(), authority2_root]);

    let report = X509PathFinder::new(X509PathFinderConfiguration {
        limit: Duration::default(),
        #[cfg(feature = "resolve")]
        aia: None,
        validator,
        certificates: cached_certificates_cross_last,
    })
    .find_sync(authority1_ee.clone())
    .unwrap();

    let found = report.found.unwrap();

    assert_eq!(0, report.failures.len());
    assert_eq!(authority1_certificates, found.path);
    assert_eq!(
        vec![
            CertificateOrigin::Target,
            CertificateOrigin::Store,
            CertificateOrigin::Store,
            CertificateOrigin::Store,
            CertificateOrigin::Store,
            CertificateOrigin::Store,
            CertificateOrigin::Store
        ],
        found.origin
    );
}

#[tokio::test]
async fn test_cross_first_dead_end_no_aia() {
    let mut authority1_certificates = CertificatePathGenerator::generate(8, "authority1")
        .unwrap()
        .into_iter()
        .map(|c| c.into())
        .collect::<Vec<Arc<crate::Certificate>>>();
    let authority1_root = authority1_certificates.pop().unwrap();
    let authority1_ee = authority1_certificates[0].clone();
    let authority1_ic = authority1_certificates[1].clone();

    let (mut authority2_certificates, mut authority2_keys) =
        CertificatePathGenerator::generate_with_keys(1, "authority2").unwrap();
    let authority2_root = authority2_certificates.pop().unwrap();
    let authority2_root_key = authority2_keys.pop().unwrap();

    let cross =
        CertificatePathGenerator::cross(&authority2_root, &authority2_root_key, &authority1_ic)
            .unwrap();

    let mut cached_certificates_cross_first = vec![Arc::new(cross.clone())];
    cached_certificates_cross_first.extend(authority1_certificates.clone());

    let validator = TestPathValidator::new(vec![authority1_root.as_ref().clone()]);

    let report = X509PathFinder::new(X509PathFinderConfiguration {
        limit: Duration::default(),
        #[cfg(feature = "resolve")]
        aia: None,
        validator,
        certificates: cached_certificates_cross_first,
    })
    .find(authority1_ee.clone())
    .await
    .unwrap();

    let found = report.found.unwrap();

    assert_eq!(1, report.failures.len());
    assert_eq!(authority1_certificates, found.path);
    assert_eq!(
        vec![
            CertificateOrigin::Target,
            CertificateOrigin::Store,
            CertificateOrigin::Store,
            CertificateOrigin::Store,
            CertificateOrigin::Store,
            CertificateOrigin::Store,
            CertificateOrigin::Store
        ],
        found.origin
    );
}

#[test]
fn test_cross_first_dead_end_no_aia_sync() {
    let mut authority1_certificates = CertificatePathGenerator::generate(8, "authority1")
        .unwrap()
        .into_iter()
        .map(|c| c.into())
        .collect::<Vec<Arc<crate::Certificate>>>();
    let authority1_root = authority1_certificates.pop().unwrap();
    let authority1_ee = authority1_certificates[0].clone();
    let authority1_ic = authority1_certificates[1].clone();

    let (mut authority2_certificates, mut authority2_keys) =
        CertificatePathGenerator::generate_with_keys(1, "authority2").unwrap();
    let authority2_root = authority2_certificates.pop().unwrap();
    let authority2_root_key = authority2_keys.pop().unwrap();

    let cross =
        CertificatePathGenerator::cross(&authority2_root, &authority2_root_key, &authority1_ic)
            .unwrap();

    let mut cached_certificates_cross_first = vec![Arc::new(cross.clone())];
    cached_certificates_cross_first.extend(authority1_certificates.clone());

    let validator = TestPathValidator::new(vec![authority1_root.as_ref().clone()]);

    let report = X509PathFinder::new(X509PathFinderConfiguration {
        limit: Duration::default(),
        #[cfg(feature = "resolve")]
        aia: None,
        validator,
        certificates: cached_certificates_cross_first,
    })
    .find_sync(authority1_ee.clone())
    .unwrap();

    let found = report.found.unwrap();

    assert_eq!(1, report.failures.len());
    assert_eq!(authority1_certificates, found.path);
    assert_eq!(
        vec![
            CertificateOrigin::Target,
            CertificateOrigin::Store,
            CertificateOrigin::Store,
            CertificateOrigin::Store,
            CertificateOrigin::Store,
            CertificateOrigin::Store,
            CertificateOrigin::Store
        ],
        found.origin
    );
}

#[cfg(feature = "resolve")]
#[tokio::test]
async fn test_direct_path_only_aia() {
    let mut certificates = CertificatePathGenerator::generate(8, "authority").unwrap();
    let root = certificates.pop().unwrap();
    let expected = certificates
        .clone()
        .into_iter()
        .map(|c| Arc::new(c))
        .collect::<Vec<Arc<crate::Certificate>>>();
    let ee = certificates.remove(0);

    let aia_kp = certificates
        .iter()
        .rev()
        .enumerate()
        .map(|(n, c)| {
            (
                Url::parse(format!("test://{}.authority", (n + 1)).as_str()).unwrap(),
                Arc::new(c.clone()),
            )
        })
        .rev()
        .collect::<Vec<(Url, Arc<crate::Certificate>)>>();

    let aia: HashMap<Url, Arc<crate::Certificate>> = HashMap::from_iter(aia_kp.clone());

    let validator = TestPathValidator::new(vec![root]);

    let mut search = X509PathFinder::new(X509PathFinderConfiguration {
        limit: Duration::default(),
        aia: Some(TestAIA {
            certificates: aia,
            sleep: None,
        }),
        validator,
        certificates: vec![],
    });

    let report = search.find(ee).await.unwrap();
    let found = report.found.unwrap();

    assert_eq!(0, report.failures.len());
    assert_eq!(expected, found.path);
    assert_eq!(
        vec![
            CertificateOrigin::Target,
            CertificateOrigin::Url(aia_kp[0].clone().0),
            CertificateOrigin::Url(aia_kp[1].clone().0),
            CertificateOrigin::Url(aia_kp[2].clone().0),
            CertificateOrigin::Url(aia_kp[3].clone().0),
            CertificateOrigin::Url(aia_kp[4].clone().0),
            CertificateOrigin::Url(aia_kp[5].clone().0),
        ],
        found.origin
    );
}

#[cfg(feature = "resolve")]
#[tokio::test]
async fn test_direct_path_partial_aia() {
    let mut certificates = CertificatePathGenerator::generate(8, "authority")
        .unwrap()
        .into_iter()
        .map(|c| c.into())
        .collect::<Vec<Arc<crate::Certificate>>>();
    let root = certificates.pop().unwrap();
    let expected = certificates.clone();
    let ee = certificates.remove(0);

    let aia_kp = certificates
        .iter()
        .rev()
        .enumerate()
        .map(|(n, c)| {
            (
                Url::parse(format!("test://{}.authority", (n + 1)).as_str()).unwrap(),
                c.clone(),
            )
        })
        .rev()
        .collect::<Vec<(Url, Arc<crate::Certificate>)>>();

    let aia: HashMap<Url, Arc<crate::Certificate>> = HashMap::from_iter(aia_kp.clone());

    let validator = TestPathValidator::new(vec![root.as_ref().clone()]);

    let mut search = X509PathFinder::new(X509PathFinderConfiguration {
        limit: Duration::default(),
        aia: Some(TestAIA {
            certificates: aia,
            sleep: None,
        }),
        validator,
        certificates: vec![certificates[2].clone(), certificates[4].clone()],
    });

    let report = search.find(ee).await.unwrap();
    let found = report.found.unwrap();

    assert_eq!(0, report.failures.len());
    assert_eq!(expected, found.path);
    assert_eq!(
        vec![
            CertificateOrigin::Target,
            CertificateOrigin::Url(aia_kp[0].clone().0),
            CertificateOrigin::Url(aia_kp[1].clone().0),
            CertificateOrigin::Store,
            CertificateOrigin::Url(aia_kp[3].clone().0),
            CertificateOrigin::Store,
            CertificateOrigin::Url(aia_kp[5].clone().0),
        ],
        found.origin
    );
}

/*

https://www.rfc-editor.org/rfc/rfc4158#section-5.2

5.2.  Loop Detection

   In a non-hierarchical PKI structure, a path-building algorithm may
   become caught in a loop without finding an existing path.  Consider
   the example below:

             +----+
             | TA |
             +----+
               |
               |
             +---+      +---+
             | A |    ->| Z |
             +---+   /  +---+
               |    /     |
               |   /      |
               V  /       V
             +---+      +---+
             | B |<-----| Y |
             +---+      +---+
               |
               |
               V
             +--------+
             | Target |
             +--------+

      Figure 15 - Loop Example
 */
#[tokio::test]
async fn escape_path_loop() {
    let (mut certificates, mut keys) =
        CertificatePathGenerator::generate_with_keys(4, "authority").unwrap();
    let ta = certificates.pop().unwrap();
    let _ta_key = keys.pop().unwrap();
    let a = certificates.pop().unwrap();
    let a_key = keys.pop().unwrap();
    let b = certificates.pop().unwrap();
    let b_key = keys.pop().unwrap();
    let target = certificates.pop().unwrap();
    let _target_key = keys.pop().unwrap();

    let z = CertificatePathGenerator::cross(&b, &b_key, &a).unwrap();
    let z_key = a_key.clone();
    let y = CertificatePathGenerator::cross(&z, &z_key, &a).unwrap();

    // path
    assert_eq!(ta.tbs_certificate.subject, a.tbs_certificate.issuer);
    assert_eq!(a.tbs_certificate.subject, b.tbs_certificate.issuer);
    assert_eq!(b.tbs_certificate.subject, target.tbs_certificate.issuer);

    // loop
    assert_eq!(b.tbs_certificate.subject, z.tbs_certificate.issuer);
    assert_eq!(z.tbs_certificate.subject, y.tbs_certificate.issuer);
    assert_eq!(y.tbs_certificate.subject, b.tbs_certificate.issuer);

    let validator = TestPathValidator::new(vec![ta]);

    let mut search = X509PathFinder::new(X509PathFinderConfiguration {
        limit: Duration::default(),
        #[cfg(feature = "resolve")]
        aia: None,
        validator: validator.clone(),
        certificates: vec![a.clone().into(), b.clone().into()],
    });

    search.find(target.clone()).await.unwrap().found.unwrap();

    let mut search = X509PathFinder::new(X509PathFinderConfiguration {
        limit: Duration::default(),
        #[cfg(feature = "resolve")]
        aia: None,
        validator,
        certificates: vec![z.into(), y.into(), a.into(), b.into()],
    });

    search.find(target).await.unwrap().found.unwrap();
}

#[test]
fn escape_path_loop_sync() {
    let (mut certificates, mut keys) =
        CertificatePathGenerator::generate_with_keys(4, "authority").unwrap();
    let ta = certificates.pop().unwrap();
    let _ta_key = keys.pop().unwrap();
    let a = certificates.pop().unwrap();
    let a_key = keys.pop().unwrap();
    let b = certificates.pop().unwrap();
    let b_key = keys.pop().unwrap();
    let target = certificates.pop().unwrap();
    let _target_key = keys.pop().unwrap();

    let z = CertificatePathGenerator::cross(&b, &b_key, &a).unwrap();
    let z_key = a_key.clone();
    let y = CertificatePathGenerator::cross(&z, &z_key, &a).unwrap();

    // path
    assert_eq!(ta.tbs_certificate.subject, a.tbs_certificate.issuer);
    assert_eq!(a.tbs_certificate.subject, b.tbs_certificate.issuer);
    assert_eq!(b.tbs_certificate.subject, target.tbs_certificate.issuer);

    // loop
    assert_eq!(b.tbs_certificate.subject, z.tbs_certificate.issuer);
    assert_eq!(z.tbs_certificate.subject, y.tbs_certificate.issuer);
    assert_eq!(y.tbs_certificate.subject, b.tbs_certificate.issuer);

    let validator = TestPathValidator::new(vec![ta]);

    let mut search = X509PathFinder::new(X509PathFinderConfiguration {
        limit: Duration::default(),
        #[cfg(feature = "resolve")]
        aia: None,
        validator: validator.clone(),
        certificates: vec![a.clone().into(), b.clone().into()],
    });

    search.find_sync(target.clone()).unwrap().found.unwrap();

    let mut search = X509PathFinder::new(X509PathFinderConfiguration {
        limit: Duration::default(),
        #[cfg(feature = "resolve")]
        aia: None,
        validator,
        certificates: vec![z.into(), y.into(), a.into(), b.into()],
    });

    search.find_sync(target).unwrap().found.unwrap();
}
