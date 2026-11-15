//! Google Cloud tokens for remote_write, as Prometheus's googleiam asks
//! for them (x/oauth2/google): from a credentials file (a service
//! account's key, signed into a JWT, or a user's refresh token), else
//! the default credentials: GOOGLE_APPLICATION_CREDENTIALS, gcloud's
//! file, the GCE metadata server.

use super::auth::{EARLY, Expiring, Tokens, form_token, json_token};
use super::{Client, Url};
use crate::encoding::base64_url;
use crate::json::Json;
use ring::rand::SystemRandom;
use ring::signature::{RSA_PKCS1_SHA256, RsaKeyPair};
use rustls::pki_types::PrivateKeyDer;
use rustls::pki_types::pem::PemObject;
use std::env;
use std::fs;
use std::io;
use std::path::Path;

const SCOPE: &str = "https://www.googleapis.com/auth/monitoring.write";
const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
/// A signed assertion's life, as x/oauth2's jws.
const ASSERTION_SECONDS: i64 = 3600;

enum Source {
    Service {
        email: String,
        key_id: String,
        key: Box<RsaKeyPair>,
        token_url: Url,
    },
    User {
        client_id: String,
        secret: String,
        refresh: String,
    },
    Metadata,
}

struct Google {
    source: Source,
    client: Client,
}

/// Tokens from `file`, or the default credentials when empty; refused
/// when the file cannot be read or is of another kind.
pub fn tokens(file: &str, client: Client) -> Result<Tokens, String> {
    let source = match file {
        "" => default_file().map_or(Ok(Source::Metadata), |f| source(&f))?,
        file => source(file)?,
    };
    let google = Google { source, client };
    Ok(Tokens::new(EARLY, Box::new(move || google.ask())))
}

fn default_file() -> Option<String> {
    if let Ok(file) = env::var("GOOGLE_APPLICATION_CREDENTIALS") {
        return Some(file);
    }
    let home = env::var("HOME").ok()?;
    let file =
        format!("{home}/.config/gcloud/application_default_credentials.json");
    Path::new(&file).exists().then_some(file)
}

fn source(file: &str) -> Result<Source, String> {
    let error = |e: &dyn std::fmt::Display| format!("{file}: {e}");
    let text = fs::read_to_string(file).map_err(|e| error(&e))?;
    let json = Json::parse(&text).ok_or_else(|| error(&"not JSON"))?;
    let get = |key| json.get(key).and_then(Json::str).unwrap_or("").to_owned();
    match get("type").as_str() {
        "service_account" => {
            let der =
                PrivateKeyDer::from_pem_slice(get("private_key").as_bytes())
                    .map_err(|e| error(&e))?;
            let PrivateKeyDer::Pkcs8(der) = der else {
                return Err(error(&"private_key: not PKCS #8"));
            };
            let key = RsaKeyPair::from_pkcs8(der.secret_pkcs8_der())
                .map_err(|e| error(&e))?;
            let key = Box::new(key);
            let token_url = match get("token_uri").as_str() {
                "" => TOKEN_URL.to_owned(),
                url => url.to_owned(),
            };
            Ok(Source::Service {
                email: get("client_email"),
                key_id: get("private_key_id"),
                key,
                token_url: Url::parse(&token_url)
                    .ok_or_else(|| error(&token_url))?,
            })
        }
        "authorized_user" => Ok(Source::User {
            client_id: get("client_id"),
            secret: get("client_secret"),
            refresh: get("refresh_token"),
        }),
        other => Err(error(&format!("credentials of type `{other}`"))),
    }
}

impl Google {
    fn ask(&self) -> io::Result<Expiring<String>> {
        match &self.source {
            Source::Service {
                email,
                key_id,
                key,
                token_url,
            } => {
                let jwt = assertion(email, key_id, key, token_url)?;
                let form = [
                    (
                        "grant_type",
                        "urn:ietf:params:oauth:grant-type:jwt-bearer",
                    ),
                    ("assertion", &jwt),
                ];
                form_token(token_url, &self.client, &pairs(&form), "")
            }
            Source::User {
                client_id,
                secret,
                refresh,
            } => {
                let form = [
                    ("grant_type", "refresh_token"),
                    ("client_id", client_id.as_str()),
                    ("client_secret", secret),
                    ("refresh_token", refresh),
                ];
                let url = Url::parse(TOKEN_URL)
                    .ok_or_else(|| io::Error::other(TOKEN_URL))?;
                form_token(&url, &self.client, &pairs(&form), "")
            }
            Source::Metadata => metadata(),
        }
    }
}

fn pairs(form: &[(&str, &str)]) -> Vec<(String, String)> {
    form.iter()
        .map(|(k, v)| ((*k).into(), (*v).into()))
        .collect()
}

/// The GCE metadata server's token for the instance's account.
fn metadata() -> io::Result<Expiring<String>> {
    let host = env::var("GCE_METADATA_HOST")
        .unwrap_or_else(|_| "metadata.google.internal".into());
    let url = format!(
        "http://{host}/computeMetadata/v1/instance/service-accounts/\
         default/token?scopes={SCOPE}"
    );
    let url = Url::parse(&url).ok_or_else(|| io::Error::other(url.clone()))?;
    let client = Client {
        timeout: std::time::Duration::from_secs(1),
        ..Client::default()
    };
    let header = "Metadata-Flavor: Google\r\n";
    json_token(&super::request(&url, &client, "GET", header, &[])?)
}

/// A JWT the service account signs with RS256 to ask for a token.
fn assertion(
    email: &str,
    key_id: &str,
    key: &RsaKeyPair,
    token_url: &Url,
) -> io::Result<String> {
    let text = |s: &str| Json::Str(s.to_owned());
    let mut header =
        vec![("alg".into(), text("RS256")), ("typ".into(), text("JWT"))];
    if !key_id.is_empty() {
        header.push(("kid".into(), text(key_id)));
    }
    let now = crate::time::now_ms() / 1000;
    let audience = format!(
        "{}://{}{}",
        if token_url.tls { "https" } else { "http" },
        token_url.host,
        token_url.path
    );
    let claims = vec![
        ("iss".into(), text(email)),
        ("scope".into(), text(SCOPE)),
        ("aud".into(), text(&audience)),
        ("iat".into(), Json::Num(now as f64)),
        ("exp".into(), Json::Num((now + ASSERTION_SECONDS) as f64)),
    ];
    let part = |json: Json| unpadded(json.go_text().as_bytes());
    let message =
        format!("{}.{}", part(Json::Obj(header)), part(Json::Obj(claims)));
    let mut signature = vec![0; key.public().modulus_len()];
    key.sign(
        &RSA_PKCS1_SHA256,
        &SystemRandom::new(),
        message.as_bytes(),
        &mut signature,
    )
    .map_err(|_| io::Error::other("google: signing failed"))?;
    Ok(format!("{message}.{}", unpadded(&signature)))
}

/// JWT's base64: URL-safe, without padding.
fn unpadded(data: &[u8]) -> String {
    base64_url(data).trim_end_matches('=').to_owned()
}
