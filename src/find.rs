use crate::api::{CertificatePathValidation, PathValidator};
use crate::certificate::Certificate;
use crate::edge::{Edge, Edges};
#[cfg(feature = "resolve")]
use crate::report::CertificateOrigin;
use crate::report::{Found, Report, ValidationFailure};
use crate::store::CertificateStore;
use crate::{X509PathFinderError, X509PathFinderResult};
#[cfg(test)]
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::vec;
#[cfg(any(test, feature = "resolve"))]
use url::Url;
#[cfg(feature = "resolve")]
use x509_client::X509ClientResult;
#[cfg(all(not(test), feature = "resolve"))]
use {
    x509_client::provided::default::DefaultX509Iterator,
    x509_client::{X509Client, X509ClientConfiguration},
};

/// [`X509PathFinder`](crate::X509PathFinder) configuration
#[derive(Clone)]
pub struct X509PathFinderConfiguration<V>
where
    V: PathValidator,
{
    /// limit runtime of path search. Actual limit will be N * HTTP timeout. See `Reqwest` docs for setting HTTP connection timeout.
    pub limit: Duration,
    /// Optional client to find additional certificates by parsing URLs from [Authority Information Access](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.2.1) extensions
    #[cfg(all(not(test), feature = "resolve"))]
    pub aia: Option<X509ClientConfiguration>,
    #[cfg(all(test, feature = "resolve"))]
    pub aia: Option<TestAIA>,
    /// [`PathValidator`](crate::api::PathValidator) implementation
    pub validator: V,
    /// Bridge and cross signed-certificates to use for path finding
    pub certificates: Vec<Arc<crate::Certificate>>,
}

/// X509 Path Finder
pub struct X509PathFinder<V>
where
    V: PathValidator,
{
    limit: Duration,
    #[cfg(all(not(test), feature = "resolve"))]
    aia: Option<X509Client<DefaultX509Iterator>>,
    #[cfg(all(test, feature = "resolve"))]
    aia: Option<TestAIA>,
    validator: V,
    store: CertificateStore,
    edges: Edges,
}

impl<V> X509PathFinder<V>
where
    V: PathValidator,
    X509PathFinderError: From<<V as PathValidator>::PathValidatorError>,
{
    /// Instantiate new X509PathFinder with configuration
    pub fn new(config: X509PathFinderConfiguration<V>) -> Self
    where
        X509PathFinderError: From<der::Error>,
    {
        X509PathFinder {
            limit: config.limit,
            #[cfg(all(not(test), feature = "resolve"))]
            aia: config.aia.map(X509Client::new),
            #[cfg(all(test, feature = "resolve"))]
            aia: config.aia,
            validator: config.validator,
            store: CertificateStore::from_iter(config.certificates.into_iter().map(|c| c.into())),
            edges: Edges::new(),
        }
    }

    /// Find certificate path, returning [`Report`](crate::report::Report)
    pub async fn find<I: Into<Arc<crate::Certificate>>>(
        &mut self,
        target: I,
    ) -> X509PathFinderResult<Report> {
        let target: Arc<crate::Certificate> = target.into();
        self.edges.start(target.into());
        let start = Instant::now();
        let mut failures = vec![];

        while let Some(edge) = self.edges.next() {
            if self.limit != Duration::ZERO && Instant::now() - start > self.limit {
                return Err(X509PathFinderError::Error("limit exceeded".to_string()));
            }

            if edge == Edge::End {
                let (path, origin) = self.edges.path(&edge);
                match self
                    .validator
                    .validate(path.iter().map(|c| c.as_ref()).collect())?
                {
                    CertificatePathValidation::Found(trust_anchor) => {
                        return Ok(Report {
                            found: Some(Found {
                                path,
                                origin,
                                trust_anchor,
                            }),
                            duration: Instant::now() - start,
                            failures,
                        });
                    }
                    CertificatePathValidation::NotFound(reason) => {
                        failures.push(ValidationFailure {
                            path,
                            origin,
                            reason,
                        });
                    }
                }
            }

            if self.edges.visited(&edge) {
                continue;
            }

            self.edges.visit(edge.clone());

            self.next(edge).await?;
        }

        Ok(Report {
            found: None,
            duration: Instant::now() - start,
            failures,
        })
    }

    /// Synchronously finds certificate path, returning [`Report`].
    ///
    /// Won't resolve AIAs.
    pub fn find_sync<I: Into<Arc<crate::Certificate>>>(
        &mut self,
        target: I,
    ) -> X509PathFinderResult<Report> {
        let target: Arc<crate::Certificate> = target.into();
        self.edges.start(target.into());
        let start = Instant::now();
        let mut failures = vec![];

        while let Some(edge) = self.edges.next() {
            if edge == Edge::End {
                let (path, origin) = self.edges.path(&edge);
                match self
                    .validator
                    .validate(path.iter().map(|c| c.as_ref()).collect())?
                {
                    CertificatePathValidation::Found(trust_anchor) => {
                        return Ok(Report {
                            found: Some(Found {
                                path,
                                origin,
                                trust_anchor,
                            }),
                            duration: Instant::now() - start,
                            failures,
                        });
                    }
                    CertificatePathValidation::NotFound(reason) => {
                        failures.push(ValidationFailure {
                            path,
                            origin,
                            reason,
                        });
                    }
                }
            }

            if self.edges.visited(&edge) {
                continue;
            }

            self.edges.visit(edge.clone());

            self.next_sync(edge)?;
        }

        Ok(Report {
            found: None,
            duration: Instant::now() - start,
            failures,
        })
    }

    async fn next(&mut self, edge: Edge) -> X509PathFinderResult<()> {
        match &edge {
            // edge is leaf certificate, search for issuer candidates
            Edge::Certificate(edge_certificate) => {
                let mut store_candidates = self.next_store(edge_certificate.clone());

                // queue issuer candidates from store or try aia
                if !store_candidates.is_empty() {
                    #[cfg(feature = "resolve")]
                    // queue any aia edges
                    store_candidates.extend(
                        edge_certificate
                            .aia()
                            .iter()
                            .map(|u| Edge::Url(u.clone().into(), edge_certificate.clone())),
                    );

                    // reverse store edges so explored by store priority
                    store_candidates.reverse();
                    self.edges.extend(edge.clone(), store_candidates);
                    Ok(())
                } else {
                    self.edges
                        .extend(edge.clone(), self.next_aia(edge_certificate.clone()));
                    Ok(())
                }
            }
            #[cfg(feature = "resolve")]
            // edge is url, download certificates, queue issuer candidates
            Edge::Url(url, edge_certificate) => {
                let url_edges = self.next_url(edge_certificate.as_ref(), url).await;
                self.edges.extend(edge, url_edges);
                Ok(())
            }
            // edge is end, stop search
            Edge::End => Ok(()),
        }
    }

    fn next_sync(&mut self, edge: Edge) -> X509PathFinderResult<()> {
        match &edge {
            // edge is leaf certificate, search for issuer candidates
            Edge::Certificate(edge_certificate) => {
                let mut store_candidates = self.next_store(edge_certificate.clone());

                // queue issuer candidates from store
                if !store_candidates.is_empty() {
                    #[cfg(feature = "resolve")]
                    // queue any aia edges
                    store_candidates.extend(
                        edge_certificate
                            .aia()
                            .iter()
                            .map(|u| Edge::Url(u.clone().into(), edge_certificate.clone())),
                    );

                    // reverse store edges so explored by store priority
                    store_candidates.reverse();
                    self.edges.extend(edge.clone(), store_candidates);
                    Ok(())
                } else {
                    self.edges
                        .extend(edge.clone(), self.next_aia(edge_certificate.clone()));
                    Ok(())
                }
            }
            #[cfg(feature = "resolve")]
            // edge is url, cannot perform synchronously
            Edge::Url(_, _) => Err(X509PathFinderError::Error(
                "cannot resolve URLs, use `find` istead".into(),
            )),
            // edge is end, stop search
            Edge::End => Ok(()),
        }
    }

    // return issuer candidates from store
    fn next_store(&self, parent_certificate: Arc<Certificate>) -> Vec<Edge> {
        self.store
            .issuers(parent_certificate.as_ref())
            .into_iter()
            .map(Edge::Certificate)
            .collect()
    }

    // download certificates, insert into store, return non self-signed issuer candidates
    #[cfg(feature = "resolve")]
    async fn next_url(&mut self, parent_certificate: &Certificate, url: &Url) -> Vec<Edge> {
        let candidates = self
            .get_all(url)
            .await
            .unwrap_or_else(|_| vec![])
            .into_iter()
            .filter_map(|candidate| {
                // filtering out self-signed
                self.store.insert(candidate).and_then(|candidate| {
                    // url is issuer, return as certificate edge
                    candidate
                        .issued(parent_certificate)
                        .then(|| Edge::Certificate(candidate))
                })
            })
            // reverse certificates so explored in order returned from server
            .rev()
            .collect::<Vec<Edge>>();

        // no issuer candidates, return end edge
        if candidates.is_empty() {
            vec![Edge::End]
        } else {
            candidates
        }
    }

    // if aia enabled, return aia edges
    #[cfg(feature = "resolve")]
    fn next_aia(&self, parent_certificate: Arc<Certificate>) -> Vec<Edge> {
        // aia disabled, return end edge
        if self.aia.is_none() {
            return vec![Edge::End];
        }

        let aia_urls = parent_certificate.aia();

        // no aia urls found, return end edge
        if aia_urls.is_empty() {
            return vec![Edge::End];
        }

        aia_urls
            .iter()
            .map(|u| Edge::Url(u.clone().into(), parent_certificate.clone()))
            // reverse urls so explored in order presented in certificate AIA extension
            .rev()
            .collect()
    }
    #[cfg(not(feature = "resolve"))]
    fn next_aia(&self, _parent_certificate: Arc<Certificate>) -> Vec<Edge> {
        vec![Edge::End]
    }

    #[cfg(all(not(test), feature = "resolve"))]
    async fn get_all(&self, url: &Url) -> X509ClientResult<Vec<Certificate>> {
        if let Some(client) = &self.aia {
            Ok(client
                .get_all(url)
                .await?
                .into_iter()
                .map(|c| {
                    let mut c = Certificate::from(Arc::new(c));
                    c.set_origin(CertificateOrigin::Url(url.clone()));
                    c
                })
                .collect())
        } else {
            Ok(vec![])
        }
    }

    #[cfg(all(test, feature = "resolve"))]
    async fn get_all(&self, url: &Url) -> X509ClientResult<Vec<Certificate>> {
        if let Some(aia) = &self.aia {
            if let Some(duration) = &aia.sleep {
                std::thread::sleep(*duration);
            }
            return Ok(aia
                .certificates
                .get(url)
                .map_or_else(std::vec::Vec::new, |c| {
                    let mut c = Certificate::from(c.clone());
                    c.set_origin(CertificateOrigin::Url(url.clone()));
                    vec![c]
                }));
        }
        Ok(vec![])
    }
}

#[cfg(test)]
#[derive(Clone)]
pub struct TestAIA {
    pub certificates: HashMap<Url, Arc<crate::Certificate>>,
    pub sleep: Option<Duration>,
}
