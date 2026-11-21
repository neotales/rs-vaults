use neotales_vaults_core::{Client, GetOptions, SecretValue};
use neotales_vaults_crypto::{
    Algorithm, CertificateRequest, certificate_der_to_pem, certificate_pem_to_der, generate_key,
    generate_self_signed, private_key_der_to_pem, private_key_pem_to_der,
};
use rcgen::PublicKeyData;

fn request(algorithm: Algorithm) -> CertificateRequest {
    CertificateRequest {
        key_id: "server-key".into(),
        common_name: "example.test".into(),
        subject_alt_names: vec!["example.test".into(), "127.0.0.1".into()],
        not_before_unix: 1_700_000_000,
        not_after_unix: 1_731_536_000,
        algorithm,
    }
}

#[test]
fn generates_matching_keys_and_verifiable_certificates() {
    for algorithm in [Algorithm::Ed25519, Algorithm::EcdsaP256] {
        let identity = generate_self_signed(&request(algorithm)).unwrap();
        let (remaining, cert) =
            x509_parser::parse_x509_certificate(&identity.certificate.data).unwrap();
        assert!(remaining.is_empty());
        cert.verify_signature(None).unwrap();
        assert_eq!(cert.validity().not_before.timestamp(), 1_700_000_000);
        assert_eq!(cert.validity().not_after.timestamp(), 1_731_536_000);
        let san = cert.subject_alternative_name().unwrap().unwrap();
        assert_eq!(san.value.general_names.len(), 2);
        let private = identity.key.private_key.as_ref().unwrap();
        let pem = private_key_der_to_pem(private).unwrap();
        assert_eq!(
            private_key_pem_to_der(&pem).unwrap().expose(),
            private.expose()
        );
        let pair = rcgen::KeyPair::from_pem(&pem).unwrap();
        assert_eq!(
            pair.subject_public_key_info(),
            *identity.key.public_key.as_ref().unwrap()
        );
        assert_eq!(pair.subject_public_key_info(), cert.public_key().raw);
        let cert_pem = certificate_der_to_pem(&identity.certificate.data).unwrap();
        assert_eq!(
            certificate_pem_to_der(&cert_pem).unwrap(),
            identity.certificate.data
        );
        assert!(!format!("{identity:?}").contains(&pem.to_string()));
    }
}

#[test]
fn rejects_invalid_requests_and_invalid_certificate_conversion() {
    let mut req = request(Algorithm::Ed25519);
    req.not_after_unix = req.not_before_unix;
    assert!(generate_self_signed(&req).is_err());
    req.not_after_unix += 1;
    req.subject_alt_names.clear();
    assert!(generate_self_signed(&req).is_err());
    assert!(generate_key("", Algorithm::Ed25519).is_err());
    assert!(certificate_der_to_pem(&[0x30, 0]).is_err());
    assert!(
        certificate_pem_to_der("-----BEGIN CERTIFICATE-----\nMAA=\n-----END CERTIFICATE-----")
            .is_err()
    );
    assert!(private_key_der_to_pem(&SecretValue::new(vec![0xff])).is_err());
}

#[test]
fn generated_identity_can_be_stored_in_age_json() {
    let temp = tempfile::tempdir().unwrap();
    let age_key = neotales_age::AgeKey::generate().unwrap();
    let driver = neotales_vaults_age_json::AgeJsonDriver::new(neotales_vaults_age_json::Config {
        vault: "work".into(),
        path: temp.path().join("vault.json"),
        recipients: vec![age_key.public_key],
        identities: vec![SecretValue::new(age_key.private_key.as_bytes().to_vec())],
    })
    .unwrap();
    let client = Client::new(driver);
    let identity = generate_self_signed(&request(Algorithm::Ed25519)).unwrap();
    client
        .set_certificate("work", "tls", &identity.certificate)
        .unwrap();
    client.set_key("work", "tls", &identity.key).unwrap();
    assert_eq!(
        client
            .get_certificate("work", "tls", &GetOptions::default())
            .unwrap()
            .value,
        identity.certificate
    );
    assert_eq!(
        client
            .get_key("work", "tls", &GetOptions::default())
            .unwrap()
            .value,
        identity.key
    );
}
