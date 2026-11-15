//! `aws login` sessions (a profile's login_session), as the SDK's
//! logincreds provider reads them: the token the AWS CLI cached, and
//! once it has expired, a new one from AWS Sign-In's
//! CreateOAuth2Token, proved by a DPoP JWT signed with the token's own
//! P-256 key, written back to the cache.

use super::auth::Expiring;
use super::azure_cert::{unpadded, uuid};
use super::sigv4::Keys;
use super::{Client, Url};
use crate::json::Json;
use crate::time;
use p256::SecretKey;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::elliptic_curve::sec1::ToSec1Point;
use ring::rand::SystemRandom;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::time::{Duration, Instant};

/// Sign-In's host for each partition, by its regions' prefix.
const HOSTS: [(&str, &str); 7] = [
    ("cn-", "signin.amazonaws.cn"),
    ("us-gov-", "signin.amazonaws-us-gov.com"),
    ("us-isob-", "signin.sc2shome.sgov.gov"),
    ("us-isof-", "signin.csphome.hci.ic.gov"),
    ("us-iso-", "signin.c2shome.ic.gov"),
    ("eu-isoe-", "signin.csphome.adc-e.uk"),
    ("eusc-", "signin.amazonaws-eusc.eu"),
];

/// The access token's fields the SDK requires, in its order.
const REQUIRED: [&str; 4] = [
    "accessKeyId",
    "secretAccessKey",
    "sessionToken",
    "accountId",
];

pub fn keys(
    session: &str,
    region: &str,
    client: &Client,
) -> io::Result<Expiring<Keys>> {
    let dir = std::env::var("AWS_LOGIN_CACHE_DIRECTORY").ok();
    let dir = dir.filter(|d| !d.is_empty()).unwrap_or_else(|| {
        let home = std::env::var("HOME").unwrap_or_default();
        format!("{home}/.aws/login/cache")
    });
    let name = crate::digest::sha256(session.trim().as_bytes());
    let file = format!("{dir}/{}.json", crate::digest::hex(&name));
    from_cache(&file, region, client)
}

fn from_cache(
    file: &str,
    region: &str,
    client: &Client,
) -> io::Result<Expiring<Keys>> {
    let error = |what: &str, e: &dyn std::fmt::Display| {
        io::Error::other(format!("{what}: {e}"))
    };
    let token = load(file).map_err(|e| error("load login token", &e))?;
    let expires_ns =
        valid(&token).map_err(|e| error("validate login token", &e))?;
    if time::now_ns() < expires_ns {
        return Ok(credentials(&token, expires_ns));
    }
    let token = refreshed(token, region, client)
        .map_err(|e| error("create oauth2 token", &e))?;
    save(file, &token).map_err(|e| error("save token", &e))?;
    let expires_ns =
        valid(&token).map_err(|e| error("validate login token", &e))?;
    Ok(credentials(&token, expires_ns))
}

fn load(file: &str) -> io::Result<Json> {
    let text = fs::read_to_string(file).map_err(|e| match e.kind() {
        io::ErrorKind::NotFound => {
            io::Error::other("token file not found, please reauthenticate")
        }
        _ => e,
    })?;
    Json::parse(&text).ok_or_else(|| io::Error::other("not JSON"))
}

/// The SDK's checks, in its order: the access token's expiry, in
/// nanoseconds since the epoch, when they pass.
fn valid(token: &Json) -> Result<i64, String> {
    let access = token.get("accessToken").filter(|a| !a.obj().is_empty());
    let Some(access) = access else {
        return Err("missing accessToken".into());
    };
    for key in REQUIRED {
        if field(access, key).is_none_or(str::is_empty) {
            return Err(format!("missing accessToken.{key}"));
        }
    }
    let expires = field(access, "expiresAt").and_then(time::parse_rfc3339);
    let expires = expires.ok_or("missing accessToken.expiresAt")?;
    for key in ["clientId", "refreshToken", "dpopKey"] {
        if field(token, key).is_none_or(str::is_empty) {
            return Err(format!("missing {key}"));
        }
    }
    Ok(expires)
}

fn field<'a>(json: &'a Json, key: &str) -> Option<&'a str> {
    json.get(key).and_then(Json::str)
}

fn credentials(token: &Json, expires_ns: i64) -> Expiring<Keys> {
    let access = token.get("accessToken");
    let text = |key| {
        let value = access.and_then(|a| a.get(key)).and_then(Json::str);
        value.unwrap_or("").to_owned()
    };
    let keys = Keys {
        id: text("accessKeyId"),
        secret: text("secretAccessKey"),
        token: text("sessionToken"),
    };
    let left = (expires_ns - time::now_ns()).max(0) as u64;
    (keys, Some(Instant::now() + Duration::from_nanos(left)))
}

/// The token with Sign-In's new keys and refresh token.
fn refreshed(token: Json, region: &str, client: &Client) -> io::Result<Json> {
    if region.is_empty() {
        return Err(io::Error::other("Invalid Configuration: Missing Region"));
    }
    let host = HOSTS.iter().find(|(prefix, _)| region.starts_with(prefix));
    let host = host.map_or("signin.aws.amazon.com", |h| h.1);
    let url = format!("https://{region}.{host}/v1/token");
    let parsed =
        Url::parse(&url).ok_or_else(|| io::Error::other(url.clone()))?;
    let given = |key| field(&token, key).unwrap_or("");
    let proof = dpop(given("dpopKey"), &url)?;
    let text = |s: &str| Json::Str(s.to_owned());
    let body = Json::Obj(vec![
        ("clientId".into(), text(given("clientId"))),
        ("grantType".into(), text("refresh_token")),
        ("refreshToken".into(), text(given("refreshToken"))),
    ]);
    let headers =
        format!("Content-Type: application/json\r\nDPoP: {proof}\r\n");
    let body = body.go_text();
    let response = super::post(&parsed, client, &headers, body.as_bytes())?;
    let answer = String::from_utf8_lossy(&response.body);
    let json = Json::parse(&answer).filter(|_| response.ok());
    let Some(json) = json else {
        return Err(refused(response.status, &answer));
    };
    Ok(updated(token, &json))
}

/// Sign-In's AccessDeniedException in the SDK's words.
fn refused(status: u16, answer: &str) -> io::Error {
    let code = Json::parse(answer);
    let code = code.as_ref().and_then(|j| j.get("error")?.str());
    let message = match code {
        Some("TOKEN_EXPIRED") => {
            "login session has expired, please reauthenticate".into()
        }
        Some("USER_CREDENTIALS_CHANGED") => {
            "login session password has changed, please reauthenticate".into()
        }
        Some("INSUFFICIENT_PERMISSIONS") => "insufficient permissions, you \
            may be missing permissions for the CreateOAuth2Token action"
            .into(),
        _ => format!("{status} {}", answer.trim()),
    };
    io::Error::other(message)
}

/// The SDK's loginToken.Update.
fn updated(token: Json, json: &Json) -> Json {
    let output = |key| json.get("accessToken").and_then(|a| a.get(key));
    let seconds = json.get("expiresIn").and_then(Json::num).unwrap_or(0.0);
    let at = time::rfc3339(time::now_ms() / 1000 + seconds as i64);
    let mut access =
        token.get("accessToken").map_or(&[][..], Json::obj).to_vec();
    for key in ["accessKeyId", "secretAccessKey", "sessionToken"] {
        set(&mut access, key, output(key).cloned().unwrap_or(Json::Null));
    }
    set(&mut access, "expiresAt", Json::Str(at));
    let mut fields = token.obj().to_vec();
    set(&mut fields, "accessToken", Json::Obj(access));
    let refresh = json.get("refreshToken").cloned().unwrap_or(Json::Null);
    set(&mut fields, "refreshToken", refresh);
    Json::Obj(fields)
}

fn set(fields: &mut Vec<(String, Json)>, key: &str, value: Json) {
    match fields.iter_mut().find(|(k, _)| k == key) {
        Some((_, old)) => *old = value,
        None => fields.push((key.to_owned(), value)),
    }
}

/// As the SDK writes it with restricted permissions.
fn save(file: &str, token: &Json) -> io::Result<()> {
    let mut out = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(file)?;
    out.write_all(token.go_text().as_bytes())
}

/// A DPoP proof (RFC 9449) for a POST to `url`, signed with the
/// token's SEC 1 PEM key.
fn dpop(key: &str, url: &str) -> io::Result<String> {
    let key = SecretKey::from_sec1_pem(key)
        .map_err(|e| io::Error::other(format!("sign dpop: parse key: {e}")))?;
    let point = key.public_key().to_sec1_point(false);
    let coordinate = |c: Option<&[u8]>| Json::Str(unpadded(c.unwrap_or(&[])));
    let text = |s: &str| Json::Str(s.to_owned());
    let jwk = Json::Obj(vec![
        ("kty".into(), text("EC")),
        ("x".into(), coordinate(point.x().map(|x| x.as_slice()))),
        ("y".into(), coordinate(point.y().map(|y| y.as_slice()))),
        ("crv".into(), text("P-256")),
    ]);
    let header = Json::Obj(vec![
        ("typ".into(), text("dpop+jwt")),
        ("alg".into(), text("ES256")),
        ("jwk".into(), jwk),
    ]);
    let payload = Json::Obj(vec![
        ("jti".into(), text(&uuid(&SystemRandom::new())?)),
        ("htm".into(), text("POST")),
        ("htu".into(), text(url)),
        ("iat".into(), Json::Num((time::now_ms() / 1000) as f64)),
    ]);
    let part = |json: Json| unpadded(json.go_text().as_bytes());
    let message = format!("{}.{}", part(header), part(payload));
    let signature: Signature = SigningKey::from(&key).sign(message.as_bytes());
    Ok(format!("{message}.{}", unpadded(&signature.to_bytes())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::VerifyingKey;
    use p256::ecdsa::signature::Verifier;

    /// openssl's P-256 key, as the AWS CLI writes it, or None where
    /// openssl is missing.
    fn key() -> Option<String> {
        let made = std::process::Command::new("openssl")
            .args(["ecparam", "-name", "prime256v1", "-genkey", "-noout"])
            .output()
            .ok()?;
        made.status
            .success()
            .then(|| String::from_utf8(made.stdout).ok())?
    }

    #[test]
    fn proves_possession() {
        let Some(pem) = key() else { return };
        let jwt = dpop(&pem, "https://a/v1/token").unwrap();
        let (message, signature) = jwt.rsplit_once('.').unwrap();
        let signature = crate::encoding::from_base64_url(signature).unwrap();
        let signature = Signature::from_slice(&signature).unwrap();
        let key = SecretKey::from_sec1_pem(&pem).unwrap();
        let verifying = VerifyingKey::from(&SigningKey::from(&key));
        verifying.verify(message.as_bytes(), &signature).unwrap();
        let header = message.split('.').next().unwrap();
        let header = crate::encoding::from_base64_url(header).unwrap();
        let header = Json::parse(&String::from_utf8(header).unwrap()).unwrap();
        let x = header.get("jwk").and_then(|j| j.get("x")?.str());
        assert_eq!(x.map(str::len), Some(43));
    }

    #[test]
    fn reads_the_cache() {
        let dir = std::env::temp_dir()
            .join(format!("ha-login-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("t.json").display().to_string();
        let later = time::rfc3339(time::now_ms() / 1000 + 600);
        let token = format!(
            r#"{{"accessToken":{{"accessKeyId":"a","secretAccessKey":"s",
            "sessionToken":"t","accountId":"1","expiresAt":"{later}"}},
            "clientId":"c","refreshToken":"r","dpopKey":"k"}}"#
        );
        fs::write(&file, token).unwrap();
        let (keys, expiry) = from_cache(&file, "", &Client::default()).unwrap();
        assert_eq!((keys.id.as_str(), keys.token.as_str()), ("a", "t"));
        assert!(expiry.is_some());
        fs::write(&file, r#"{"accessToken":{"accessKeyId":"a"}}"#).unwrap();
        let error = from_cache(&file, "", &Client::default()).err();
        assert_eq!(
            error.map(|e| e.to_string()).as_deref().unwrap_or(""),
            "validate login token: missing accessToken.secretAccessKey"
        );
        fs::remove_dir_all(dir).unwrap();
    }
}
