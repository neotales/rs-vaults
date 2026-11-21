use crate::{Error, ErrorKind, Result};
use percent_encoding::percent_decode_str;
use std::str::FromStr;

/// Kind of resource addressed by a vault reference.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceKind {
    /// A secret value.
    Secret,
    /// A certificate.
    Certificate,
    /// A cryptographic key.
    Key,
}

/// Parsed `nv://vault/{secrets|certs|keys}/name[/version]` reference.
///
/// Each path component is percent-decoded independently. Query parameters are
/// retained in order for the application or driver to interpret; parsing does
/// not apply them to a request or resolve the named vault.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VaultUri {
    /// Configured vault name.
    pub vault: String,
    /// Resource category.
    pub kind: ResourceKind,
    /// Resource name.
    pub name: String,
    /// Optional resource version.
    pub version: Option<String>,
    /// Decoded query parameters. Repeated names are preserved.
    pub params: Vec<(String, String)>,
}

fn invalid() -> Error {
    Error::new(ErrorKind::InvalidInput, "invalid vault URI")
}

fn decode(input: &str) -> Result<String> {
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len()
                || !bytes[i + 1].is_ascii_hexdigit()
                || !bytes[i + 2].is_ascii_hexdigit()
            {
                return Err(invalid());
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    let value = percent_decode_str(input)
        .decode_utf8()
        .map_err(|_| invalid())?
        .into_owned();
    if value.chars().any(char::is_control) {
        return Err(invalid());
    }
    Ok(value)
}

fn component(input: &str) -> Result<String> {
    let value = decode(input)?;
    if value.is_empty() || value == "." || value == ".." || value.contains(['/', '\\']) {
        return Err(invalid());
    }
    Ok(value)
}

impl FromStr for VaultUri {
    type Err = Error;
    fn from_str(input: &str) -> Result<Self> {
        let rest = input.strip_prefix("nv://").ok_or_else(invalid)?;
        if rest.contains('#') {
            return Err(invalid());
        }
        let (path, query) = rest
            .split_once('?')
            .map_or((rest, None), |(p, q)| (p, Some(q)));
        let parts: Vec<_> = path.split('/').collect();
        if !(parts.len() == 3 || parts.len() == 4) {
            return Err(invalid());
        }
        let vault = component(parts[0])?;
        // Avoid authority syntax such as userinfo or ports.
        if vault.contains(['@', ':', '?', '#']) {
            return Err(invalid());
        }
        let kind = match parts[1] {
            "secrets" => ResourceKind::Secret,
            "certs" => ResourceKind::Certificate,
            "keys" => ResourceKind::Key,
            _ => return Err(invalid()),
        };
        let name = component(parts[2])?;
        let version = parts.get(3).map(|part| component(part)).transpose()?;
        let mut params = Vec::new();
        if let Some(query) = query {
            if query.is_empty() {
                return Err(invalid());
            }
            for pair in query.split('&') {
                let (key, value) = pair.split_once('=').ok_or_else(invalid)?;
                let key = decode(key)?;
                if key.is_empty() {
                    return Err(invalid());
                }
                params.push((key, decode(value)?));
            }
        }
        Ok(Self {
            vault,
            kind,
            name,
            version,
            params,
        })
    }
}
