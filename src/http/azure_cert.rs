//! Azure AD client assertions signed with a certificate's key, as
//! azidentity's EnvironmentCredential loads it (PEM, else PKCS #12)
//! and MSAL Go signs it: PS256, the certificate's SHA-256 as x5t#S256.

use crate::encoding::{base64, base64_url};
use crate::json::Json;
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{RSA_PSS_SHA256, RsaKeyPair};
use rustls::pki_types::pem::{PemObject, SectionKind};
use std::fs;
use std::io;

/// An assertion's life, as MSAL Go's.
const ASSERTION_SECONDS: i64 = 600;

/// The certificate's signing key, with the certificates as x5c lists
/// them: the key's own first.
pub struct Certificate {
    key: RsaKeyPair,
    chain: Vec<Vec<u8>>,
}

pub fn load(path: &str, password: &str) -> io::Result<Certificate> {
    let error = |e: &dyn std::fmt::Display| {
        io::Error::other(format!("failed to parse {path:?} due to error {e}"))
    };
    let data = fs::read(path).map_err(|e| {
        io::Error::other(format!(
            "failed to read certificate file {path:?}: {e}"
        ))
    })?;
    let (certs, key) = match password.is_empty() {
        true => pem(&data).unwrap_or_else(|| pkcs12(&data, "")),
        false => pkcs12(&data, password),
    }
    .map_err(|e| error(&e))?;
    let key = key.ok_or_else(|| error(&"found no private key"))?;
    if certs.is_empty() {
        return Err(error(&"found no certificate"));
    }
    let public = key.public().as_ref().to_vec();
    let own = certs
        .iter()
        .position(|cert| cert.windows(public.len()).any(|w| w == public))
        .ok_or_else(|| error(&"key doesn't match any certificate"))?;
    let mut chain = certs;
    let first = chain.remove(own);
    chain.insert(0, first);
    Ok(Certificate { key, chain })
}

type Parsed = (Vec<Vec<u8>>, Option<RsaKeyPair>);

/// PEM blocks, or None when the data has none.
fn pem(data: &[u8]) -> Option<io::Result<Parsed>> {
    let mut certs = Vec::new();
    let mut key = None;
    for section in <(SectionKind, Vec<u8>)>::pem_slice_iter(data) {
        let Ok((kind, der)) = section else { break };
        match kind {
            SectionKind::Certificate => certs.push(der),
            SectionKind::PrivateKey | SectionKind::RsaPrivateKey => {
                if key.is_some() {
                    let message = "certData contains multiple private keys";
                    return Some(Err(io::Error::other(message)));
                }
                key = Some(der_key(kind, &der));
            }
            _ => {}
        }
    }
    if certs.is_empty() && key.is_none() {
        return None;
    }
    Some(key.transpose().map(|key| (certs, key)))
}

fn der_key(kind: SectionKind, der: &[u8]) -> io::Result<RsaKeyPair> {
    let found = match kind {
        SectionKind::PrivateKey => RsaKeyPair::from_pkcs8(der),
        _ => RsaKeyPair::from_der(der),
    };
    found.map_err(|_| io::Error::other("key must be an RSA key"))
}

#[cfg(feature = "pkcs12")]
fn pkcs12(data: &[u8], password: &str) -> io::Result<Parsed> {
    use p12_keystore::{KeyStore, Pkcs12ImportPolicy};
    let store =
        KeyStore::from_pkcs12(data, password, Pkcs12ImportPolicy::Relaxed)
            .map_err(|e| io::Error::other(e.to_string()))?;
    let Some((_, chain)) = store.private_key_chain() else {
        return Ok((Vec::new(), None));
    };
    let certs = chain.certs().iter().map(|c| c.as_der().to_vec()).collect();
    let key = der_key(SectionKind::PrivateKey, chain.key().as_der())?;
    Ok((certs, Some(key)))
}

#[cfg(not(feature = "pkcs12"))]
fn pkcs12(_: &[u8], _: &str) -> io::Result<Parsed> {
    Err(io::Error::other(
        "PKCS #12 certificates need feature pkcs12",
    ))
}

impl Certificate {
    /// A JWT for `audience` (the token endpoint) from `client_id`,
    /// with the chain in x5c when `send_chain`.
    pub fn assertion(
        &self,
        audience: &str,
        client_id: &str,
        send_chain: bool,
    ) -> io::Result<String> {
        let text = |s: &str| Json::Str(s.to_owned());
        let thumbprint = crate::digest::sha256(&self.chain[0]);
        let mut header = vec![("alg".into(), text("PS256"))];
        header.push(("typ".into(), text("JWT")));
        if send_chain {
            let chain = self.chain.iter().map(|c| text(&base64(c)));
            header.push(("x5c".into(), Json::Arr(chain.collect())));
        }
        header.push(("x5t#S256".into(), text(&base64(&thumbprint))));
        let now = crate::time::now_ms() / 1000;
        let rng = SystemRandom::new();
        let claims = vec![
            ("aud".into(), text(audience)),
            ("exp".into(), Json::Num((now + ASSERTION_SECONDS) as f64)),
            ("iss".into(), text(client_id)),
            ("jti".into(), text(&uuid(&rng)?)),
            ("nbf".into(), Json::Num(now as f64)),
            ("sub".into(), text(client_id)),
        ];
        let part = |json: Json| unpadded(json.go_text().as_bytes());
        let message =
            format!("{}.{}", part(Json::Obj(header)), part(Json::Obj(claims)));
        let mut signature = vec![0; self.key.public().modulus_len()];
        self.key
            .sign(&RSA_PSS_SHA256, &rng, message.as_bytes(), &mut signature)
            .map_err(|_| io::Error::other("unable to sign JWT token"))?;
        Ok(format!("{message}.{}", unpadded(&signature)))
    }
}

/// A random (version 4) UUID.
pub fn uuid(rng: &SystemRandom) -> io::Result<String> {
    let mut b = [0u8; 16];
    rng.fill(&mut b)
        .map_err(|_| io::Error::other("no randomness"))?;
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let hex = crate::digest::hex(&b);
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    ))
}

/// JWT's base64: URL-safe, without padding.
pub fn unpadded(data: &[u8]) -> String {
    base64_url(data).trim_end_matches('=').to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{RSA_PSS_2048_8192_SHA256, UnparsedPublicKey};
    use std::process::Command;

    /// openssl's key and certificate, or None where it is missing.
    fn made(dir: &std::path::Path) -> Option<String> {
        let (key, cert) = (dir.join("k.pem"), dir.join("c.pem"));
        let made = Command::new("openssl")
            .args(["req", "-x509", "-newkey", "rsa:2048", "-nodes"])
            .args(["-subj", "/CN=t", "-days", "1", "-keyout"])
            .args([&key, &std::path::PathBuf::from("-out"), &cert])
            .output()
            .ok()?;
        if !made.status.success() {
            return None;
        }
        let both = [fs::read(&cert).ok()?, fs::read(&key).ok()?].concat();
        let path = dir.join("both.pem");
        fs::write(&path, both).ok()?;
        Some(path.display().to_string())
    }

    #[test]
    fn signs_assertions() {
        let dir = std::env::temp_dir()
            .join(format!("ha-azure-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let Some(path) = made(&dir) else {
            return fs::remove_dir_all(dir).unwrap();
        };
        let cert = load(&path, "").unwrap();
        let jwt = cert.assertion("https://a/t", "id", true).unwrap();
        let (message, signature) = jwt.rsplit_once('.').unwrap();
        let header = message.split('.').next().unwrap();
        let header = crate::encoding::from_base64_url(header).unwrap();
        let header = String::from_utf8(header).unwrap();
        let thumbprint = base64(&crate::digest::sha256(&cert.chain[0]));
        assert!(header.contains(&thumbprint), "{header}");
        let signature = crate::encoding::from_base64_url(signature).unwrap();
        let public = cert.key.public().as_ref();
        UnparsedPublicKey::new(&RSA_PSS_2048_8192_SHA256, public)
            .verify(message.as_bytes(), &signature)
            .unwrap();
        assert!(load(&dir.join("k.pem").display().to_string(), "").is_err());
        #[cfg(feature = "pkcs12")]
        {
            let pfx = dir.join("c.pfx");
            let exported = Command::new("openssl")
                .args(["pkcs12", "-export", "-passout", "pass:p", "-in"])
                .args([&path, "-out", &pfx.display().to_string()])
                .status()
                .unwrap();
            assert!(exported.success());
            let from_pfx = load(&pfx.display().to_string(), "p").unwrap();
            assert_eq!(from_pfx.chain, cert.chain);
        }
        fs::remove_dir_all(dir).unwrap();
    }
}
