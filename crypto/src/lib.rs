//! Local key generation and self-signed X.509 certificate utilities.
#![forbid(unsafe_code)]

use neotales_vaults_core::{Certificate, Error, ErrorKind, Key, Result, SecretValue};
use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, KeyPair, PublicKeyData,
};
use time::OffsetDateTime;
use x509_parser::parse_x509_certificate;
use zeroize::Zeroizing;

/// Supported algorithms for generated signing keys.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Algorithm {
    /// Ed25519.
    Ed25519,
    /// ECDSA over NIST P-256 with SHA-256.
    EcdsaP256,
}

/// Parameters for a self-signed leaf certificate.
#[derive(Clone, Debug)]
pub struct CertificateRequest {
    /// Key identifier returned in the core `Key` object.
    pub key_id: String,
    /// Distinguished name common name.
    pub common_name: String,
    /// DNS names or IP addresses for subject alternative names; at least one.
    pub subject_alt_names: Vec<String>,
    /// Inclusive start of validity, in Unix seconds.
    pub not_before_unix: i64,
    /// End of validity, in Unix seconds. Must follow `not_before_unix`.
    pub not_after_unix: i64,
    /// Algorithm used for the key and certificate signature.
    pub algorithm: Algorithm,
}

/// A generated self-signed certificate and its matching exportable key.
#[derive(Clone, Debug)]
pub struct GeneratedIdentity {
    /// DER-encoded X.509 certificate.
    pub certificate: Certificate,
    /// PKCS#8 DER private key and SubjectPublicKeyInfo DER public key.
    pub key: Key,
}

fn invalid(message: &'static str) -> Error {
    Error::new(ErrorKind::InvalidInput, message)
}
fn failure(message: &'static str) -> Error {
    Error::new(ErrorKind::Provider, message)
}

fn create_key(algorithm: Algorithm) -> Result<Zeroizing<KeyPair>> {
    let algorithm = match algorithm {
        Algorithm::Ed25519 => &rcgen::PKCS_ED25519,
        Algorithm::EcdsaP256 => &rcgen::PKCS_ECDSA_P256_SHA256,
    };
    Ok(Zeroizing::new(
        KeyPair::generate_for(algorithm).map_err(|_| failure("key generation failed"))?,
    ))
}

fn export_key(id: &str, key: &KeyPair) -> Key {
    Key {
        id: id.to_owned(),
        public_key: Some(key.subject_public_key_info()),
        private_key: Some(SecretValue::new(key.serialize_der())),
    }
}

/// Generates an exportable PKCS#8 key and SubjectPublicKeyInfo public key.
pub fn generate_key(id: &str, algorithm: Algorithm) -> Result<Key> {
    if id.is_empty() {
        return Err(invalid("key ID must not be empty"));
    }
    let key = create_key(algorithm)?;
    Ok(export_key(id, &key))
}

/// Generates a self-signed end-entity TLS server certificate and matching key.
///
/// This creates no trust relationship. Callers must choose how to distribute
/// and trust the certificate, and should choose an appropriate lifetime.
pub fn generate_self_signed(request: &CertificateRequest) -> Result<GeneratedIdentity> {
    if request.key_id.is_empty()
        || request.common_name.is_empty()
        || request.subject_alt_names.is_empty()
        || request
            .subject_alt_names
            .iter()
            .any(|name| name.is_empty() || name.chars().any(char::is_control))
        || request.not_after_unix <= request.not_before_unix
    {
        return Err(invalid("invalid certificate request"));
    }
    let not_before = OffsetDateTime::from_unix_timestamp(request.not_before_unix)
        .map_err(|_| invalid("invalid certificate validity"))?;
    let not_after = OffsetDateTime::from_unix_timestamp(request.not_after_unix)
        .map_err(|_| invalid("invalid certificate validity"))?;
    let key = create_key(request.algorithm)?;
    let mut params = CertificateParams::new(request.subject_alt_names.clone())
        .map_err(|_| invalid("invalid certificate subject alternative name"))?;
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, request.common_name.clone());
    params.distinguished_name = name;
    params.not_before = not_before;
    params.not_after = not_after;
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let cert = params
        .self_signed(&*key)
        .map_err(|_| failure("certificate generation failed"))?;
    Ok(GeneratedIdentity {
        certificate: Certificate {
            data: cert.der().as_ref().to_vec(),
            content_type: Some("application/pkix-cert".into()),
        },
        key: export_key(&request.key_id, &key),
    })
}

fn validate_certificate(bytes: &[u8]) -> Result<()> {
    let (remaining, _) =
        parse_x509_certificate(bytes).map_err(|_| invalid("invalid X.509 certificate"))?;
    if !remaining.is_empty() {
        return Err(invalid("trailing certificate data"));
    }
    Ok(())
}

/// Converts one DER-encoded X.509 certificate to PEM after structural parsing.
///
/// This does not verify its signature, validity, or chain of trust.
pub fn certificate_der_to_pem(der: &[u8]) -> Result<String> {
    validate_certificate(der)?;
    neotales_x509::pem::encode("CERTIFICATE", der)
        .map_err(|_| invalid("certificate cannot be encoded as PEM"))
}

/// Converts one PEM-encoded X.509 certificate to DER after structural parsing.
///
/// This does not verify its signature, validity, or chain of trust.
pub fn certificate_pem_to_der(pem: &str) -> Result<Vec<u8>> {
    let der = neotales_x509::pem::decode_der(pem, "CERTIFICATE")
        .map_err(|_| invalid("invalid certificate PEM"))?;
    validate_certificate(&der)?;
    Ok(der)
}

/// Converts one PKCS#8 DER private key to PEM. The return value zeroizes on drop.
///
/// This checks DER framing, not that the key's algorithm is supported.
pub fn private_key_der_to_pem(der: &SecretValue) -> Result<Zeroizing<String>> {
    neotales_x509::pem::validate_der(der.expose())
        .map_err(|_| invalid("invalid private key DER"))?;
    Ok(Zeroizing::new(
        neotales_x509::pem::encode("PRIVATE KEY", der.expose())
            .map_err(|_| invalid("private key cannot be encoded as PEM"))?,
    ))
}

/// Converts one PKCS#8 PEM private key to DER, returned as a secret value.
///
/// This checks DER framing, not that the key's algorithm is supported.
pub fn private_key_pem_to_der(pem: &str) -> Result<SecretValue> {
    let der = neotales_x509::pem::decode_der(pem, "PRIVATE KEY")
        .map_err(|_| invalid("invalid private key PEM"))?;
    Ok(SecretValue::new(der))
}
