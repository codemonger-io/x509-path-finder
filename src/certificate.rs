use crate::report::CertificateOrigin;
#[cfg(feature = "resolve")]
use der::oid::db::rfc5280::{ID_AD_CA_ISSUERS, ID_PE_AUTHORITY_INFO_ACCESS};
use der::{Decode, DecodeValue, Encode, Header, Length, Reader, Writer};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
#[cfg(feature = "resolve")]
use url::Url;
use x509_cert::ext::pkix::name::GeneralName;
#[cfg(feature = "resolve")]
use x509_cert::ext::pkix::AuthorityInfoAccessSyntax;

#[derive(Clone, Debug)]
pub struct Certificate {
    inner: Arc<crate::Certificate>,
    issuer: String,
    subject: String,
    #[cfg(feature = "resolve")]
    aia: Vec<Url>,
    ord: usize,
    hash: Vec<u8>,
    origin: CertificateOrigin,
}

impl Certificate {
    pub fn issued(&self, subject: &Self) -> bool {
        self.subject == subject.issuer
    }
    #[cfg(feature = "resolve")]
    pub fn aia(&self) -> &[Url] {
        self.aia.as_slice()
    }

    #[cfg(feature = "resolve")]
    fn parse_aia(certificate: &crate::Certificate) -> Vec<Url> {
        match &certificate.tbs_certificate.extensions {
            None => vec![],
            Some(extensions) => extensions
                .iter()
                .filter_map(|e| {
                    if e.extn_id == ID_PE_AUTHORITY_INFO_ACCESS {
                        AuthorityInfoAccessSyntax::from_der(e.extn_value.as_ref())
                            .map_or_else(|_| None, |i| Some(i.0))
                    } else {
                        None
                    }
                })
                .flatten()
                .filter_map(|i| {
                    if i.access_method == ID_AD_CA_ISSUERS {
                        if let GeneralName::UniformResourceIdentifier(uri) = i.access_location {
                            Url::parse(uri.as_str()).ok()
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                })
                .collect(),
        }
    }

    pub fn inner(&self) -> &Arc<crate::Certificate> {
        &self.inner
    }

    pub fn set_ord(&mut self, ord: usize) {
        self.ord = ord;
    }

    pub fn origin(&self) -> &CertificateOrigin {
        &self.origin
    }

    pub fn set_origin(&mut self, origin: CertificateOrigin) {
        self.origin = origin;
    }
}

impl Encode for Certificate {
    fn encoded_len(&self) -> der::Result<Length> {
        self.inner.encoded_len()
    }

    fn encode(&self, encoder: &mut impl Writer) -> der::Result<()> {
        self.inner.encode(encoder)
    }
}

impl<'r> Decode<'r> for Certificate {
    fn decode<R: Reader<'r>>(reader: &mut R) -> der::Result<Self> {
        let header = Header::decode(reader)?;
        let inner = Arc::new(crate::Certificate::decode_value(reader, header)?);
        Ok(inner.into())
    }
}

impl PartialEq for Certificate {
    fn eq(&self, other: &Self) -> bool {
        self.inner.eq(&other.inner)
    }
}

impl Eq for Certificate {}

impl PartialOrd for Certificate {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Certificate {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.eq(other) {
            return Ordering::Equal;
        }

        if self.ord > other.ord {
            return Ordering::Greater;
        }

        Ordering::Less
    }
}

impl Hash for Certificate {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.hash.hash(state)
    }
}

impl From<Arc<crate::Certificate>> for Certificate {
    fn from(inner: Arc<crate::Certificate>) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(inner.signature.raw_bytes());
        Self {
            issuer: inner.tbs_certificate.issuer.to_string(),
            subject: inner.tbs_certificate.subject.to_string(),
            #[cfg(feature = "resolve")]
            aia: Self::parse_aia(&inner),
            inner,
            ord: 0,
            hash: hasher.finalize().to_vec(),
            origin: CertificateOrigin::Unknown,
        }
    }
}
