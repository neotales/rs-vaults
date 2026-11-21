//! Local authenticated encryption using an explicitly versioned vault secret.
#![forbid(unsafe_code)]

use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use neotales_vaults_core::{Client, Error, ErrorKind, GetOptions, Result, SecretValue};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};
use zeroize::Zeroizing;

const MAX_VALUE: usize = 4 * 1024 * 1024;
const MAX_ENVELOPE: usize = 6 * 1024 * 1024;

/// Identifies a specific, immutable key version in a configured vault.
#[derive(Clone, Debug)]
pub struct Config {
    /// Vault name as understood by the supplied client.
    pub vault: String,
    /// Secret containing the base64-encoded 32-byte encryption key.
    pub key_name: String,
    /// Explicit provider version. Keep this version available for decryption.
    pub key_version: String,
}

/// Encrypts values using a key fetched through the supplied vault client.
pub struct LocalCrypto {
    client: Client,
    config: Config,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    format: u8,
    nonce: String,
    ciphertext: String,
}

fn err(kind: ErrorKind, message: &'static str) -> Error {
    Error::new(kind, message)
}

/// Generate a fresh base64-encoded 256-bit key for storage as a vault secret.
///
/// The caller provisions the returned value in the chosen secret manager and
/// records the resulting immutable version. Never overwrite a key version
/// needed to decrypt existing data.
pub fn generate_key() -> Result<SecretValue> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    getrandom::fill(bytes.as_mut())
        .map_err(|_| err(ErrorKind::Provider, "random number generation failed"))?;
    Ok(SecretValue::new(
        STANDARD.encode(bytes.as_ref()).into_bytes(),
    ))
}

impl LocalCrypto {
    /// Create a cipher bound to a concrete key version.
    pub fn new(client: Client, config: Config) -> Result<Self> {
        if [&config.vault, &config.key_name, &config.key_version]
            .iter()
            .any(|s| s.is_empty() || s.len() > 1024)
        {
            return Err(err(
                ErrorKind::InvalidInput,
                "invalid encryption key reference",
            ));
        }
        Ok(Self { client, config })
    }

    fn aad(&self, context: &[u8]) -> Result<Vec<u8>> {
        if context.len() > 64 * 1024 {
            return Err(err(ErrorKind::InvalidInput, "encryption context too large"));
        }
        let mut aad = b"neotales-vaults-local-crypto-v1".to_vec();
        for part in [
            self.config.vault.as_bytes(),
            self.config.key_name.as_bytes(),
            self.config.key_version.as_bytes(),
            context,
        ] {
            aad.extend_from_slice(&(part.len() as u64).to_be_bytes());
            aad.extend_from_slice(part);
        }
        Ok(aad)
    }

    fn cipher(&self) -> Result<Aes256Gcm> {
        let response = self.client.get_with(
            &self.config.vault,
            &self.config.key_name,
            &GetOptions {
                version: Some(self.config.key_version.clone()),
                retry: None,
            },
        )?;
        if response.metadata.version.as_deref() != Some(self.config.key_version.as_str()) {
            return Err(err(
                ErrorKind::Provider,
                "key provider returned an unexpected version",
            ));
        }
        let key = Zeroizing::new(
            STANDARD
                .decode(response.value.expose())
                .map_err(|_| err(ErrorKind::InvalidInput, "vault key is not valid base64"))?,
        );
        Aes256Gcm::new_from_slice(&key)
            .map_err(|_| err(ErrorKind::InvalidInput, "vault key must contain 32 bytes"))
    }

    /// Encrypt a value into a JSON envelope. A fresh random nonce is used per call.
    pub fn encrypt(&self, value: &SecretValue, context: &[u8]) -> Result<Vec<u8>> {
        if value.expose().len() > MAX_VALUE {
            return Err(err(ErrorKind::InvalidInput, "value too large"));
        }
        let aad = self.aad(context)?;
        let cipher = self.cipher()?;
        let mut nonce = [0u8; 12];
        getrandom::fill(&mut nonce)
            .map_err(|_| err(ErrorKind::Provider, "random number generation failed"))?;
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: value.expose(),
                    aad: &aad,
                },
            )
            .map_err(|_| err(ErrorKind::Provider, "local encryption failed"))?;
        serde_json::to_vec(&Envelope {
            format: 1,
            nonce: STANDARD.encode(nonce),
            ciphertext: STANDARD.encode(ciphertext),
        })
        .map_err(|_| err(ErrorKind::Provider, "envelope encoding failed"))
    }

    /// Authenticate and decrypt a JSON envelope using the same context and key reference.
    pub fn decrypt(&self, envelope: &[u8], context: &[u8]) -> Result<SecretValue> {
        if envelope.len() > MAX_ENVELOPE {
            return Err(err(ErrorKind::InvalidInput, "envelope too large"));
        }
        let aad = self.aad(context)?;
        let envelope: Envelope = serde_json::from_slice(envelope)
            .map_err(|_| err(ErrorKind::InvalidInput, "invalid encrypted envelope"))?;
        if envelope.format != 1 {
            return Err(err(
                ErrorKind::Unsupported,
                "unsupported encrypted envelope format",
            ));
        }
        let nonce = STANDARD
            .decode(envelope.nonce)
            .map_err(|_| err(ErrorKind::InvalidInput, "invalid encrypted envelope"))?;
        if nonce.len() != 12 {
            return Err(err(ErrorKind::InvalidInput, "invalid encrypted envelope"));
        }
        let ciphertext = STANDARD
            .decode(envelope.ciphertext)
            .map_err(|_| err(ErrorKind::InvalidInput, "invalid encrypted envelope"))?;
        if ciphertext.len() > MAX_VALUE + 16 {
            return Err(err(ErrorKind::InvalidInput, "encrypted value too large"));
        }
        let plain = self
            .cipher()?
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| err(ErrorKind::Provider, "encrypted value authentication failed"))?;
        Ok(SecretValue::new(plain))
    }

    /// Validate and encrypt a JSON document, creating a new encrypted file.
    ///
    /// The destination must not already exist. A temporary file is written in
    /// the same directory and atomically persisted without replacing a file.
    /// This is an encrypted whole-document file, not a versioned vault driver.
    pub fn encrypt_json_file(
        &self,
        json: &SecretValue,
        context: &[u8],
        destination: &Path,
    ) -> Result<()> {
        validate_json(json.expose())?;
        let encrypted = self.encrypt(json, context)?;
        let parent = destination
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let mut file = tempfile::NamedTempFile::new_in(parent)
            .map_err(|_| err(ErrorKind::Provider, "encrypted file could not be created"))?;
        file.write_all(&encrypted)
            .and_then(|_| file.as_file().sync_all())
            .map_err(|_| err(ErrorKind::Provider, "encrypted file could not be written"))?;
        file.persist_noclobber(destination)
            .map_err(|_| err(ErrorKind::Provider, "encrypted file could not be installed"))?;
        Ok(())
    }

    /// Read, authenticate and validate an encrypted JSON document.
    ///
    /// The returned plaintext remains in memory; this method writes no plaintext file.
    pub fn decrypt_json_file(&self, source: &Path, context: &[u8]) -> Result<SecretValue> {
        let file = File::open(source)
            .map_err(|_| err(ErrorKind::Provider, "encrypted file could not be opened"))?;
        let mut input = Vec::new();
        file.take(MAX_ENVELOPE as u64 + 1)
            .read_to_end(&mut input)
            .map_err(|_| err(ErrorKind::Provider, "encrypted file could not be read"))?;
        let plain = self.decrypt(&input, context)?;
        validate_json(plain.expose())?;
        Ok(plain)
    }
}

fn validate_json(input: &[u8]) -> Result<()> {
    if input.len() > MAX_VALUE {
        return Err(err(ErrorKind::InvalidInput, "JSON document too large"));
    }
    let mut deserializer = serde_json::Deserializer::from_slice(input);
    serde::de::IgnoredAny::deserialize(&mut deserializer)
        .and_then(|_| deserializer.end())
        .map_err(|_| err(ErrorKind::InvalidInput, "invalid JSON document"))
}
