//! AWS Signature Version 4, as Prometheus's sigv4 signs remote writes:
//! keys from the configuration, else the SDK's chain (environment,
//! shared credentials file, web identity, ECS, EC2's metadata), maybe
//! swapped for a role's through STS AssumeRole.

use super::auth::{Expiring, Request};
use super::{Client, Url};
use crate::digest::{hex, hmac_sha256, sha256};
use crate::encoding::{query_escape, unescape, uri_escape};
use crate::json::Json;
use crate::time;
use std::env;
use std::fs;
use std::io;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Keys are asked for again this long before they expire.
const EARLY: Duration = Duration::from_secs(300);
/// Metadata servers answer at once or are not there.
const METADATA_TIMEOUT: Duration = Duration::from_secs(1);
const STS_VERSION: &str = "2011-06-15";

#[derive(Clone, Default)]
pub struct Keys {
    pub id: String,
    pub secret: String,
    pub token: String,
}

pub struct Role {
    pub arn: String,
    pub external_id: String,
    pub session_name: String,
    pub tags: Vec<(String, String)>,
}

/// What the configuration says; empty strings are unset.
pub struct Settings {
    pub region: String,
    pub service: String,
    pub keys: Option<Keys>,
    pub profile: String,
    pub role: Option<Role>,
    pub fips: bool,
    /// How STS and the metadata servers are reached.
    pub client: Client,
}

pub struct SigV4 {
    settings: Settings,
    kept: Mutex<Option<Expiring<Keys>>>,
}

impl SigV4 {
    /// Refused as Prometheus refuses it: without a region, or when no
    /// keys can be found now.
    pub fn new(mut settings: Settings) -> Result<SigV4, String> {
        if settings.profile.is_empty() {
            settings.profile =
                env::var("AWS_PROFILE").unwrap_or_else(|_| "default".into());
        }
        if settings.region.is_empty() {
            settings.region = region(&settings.profile);
        }
        if settings.region.is_empty() {
            return Err("region not configured in sigv4 or in default \
                credentials chain"
                .into());
        }
        if settings.service.is_empty() {
            settings.service = "aps".into();
        }
        let sigv4 = SigV4 {
            settings,
            kept: Mutex::new(None),
        };
        sigv4
            .base()
            .map_err(|e| format!("could not get SigV4 credentials: {e}"))?;
        Ok(sigv4)
    }

    /// X-Amz-Date, the session token if any, and Authorization.
    pub fn sign(&self, request: &Request) -> io::Result<String> {
        let keys = self.keys()?;
        let s = &self.settings;
        let now_s = time::now_ms() / 1000;
        Ok(signed(&keys, &s.region, &s.service, request, now_s))
    }

    fn keys(&self) -> io::Result<Keys> {
        let mut kept = self.kept.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((keys, expiry)) = kept.as_ref() {
            if expiry.is_none_or(|at| Instant::now() + EARLY < at) {
                return Ok(keys.clone());
            }
        }
        let base = self.base()?;
        let fresh = match &self.settings.role {
            None => base,
            Some(role) => self.assume(role, &base.0)?,
        };
        *kept = Some(fresh.clone());
        Ok(fresh.0)
    }

    fn base(&self) -> io::Result<Expiring<Keys>> {
        if let Some(keys) = &self.settings.keys {
            return Ok((keys.clone(), None));
        }
        if let Some(keys) = from_env().or_else(|| from_file(self.profile())) {
            return Ok((keys, None));
        }
        let web = ["AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ROLE_ARN"];
        if let [Ok(file), Ok(arn)] = web.map(env::var) {
            return self.web_identity(&file, &arn);
        }
        if let Some((url, header)) = container_url() {
            let headers = format!("Accept: application/json\r\n{header}");
            return metadata_keys(&url, &self.metadata_client(), &headers);
        }
        self.ec2()
    }

    fn profile(&self) -> &str {
        &self.settings.profile
    }

    fn metadata_client(&self) -> Client {
        Client {
            timeout: METADATA_TIMEOUT,
            ..Client::default()
        }
    }

    /// IMDSv2: a session token, then the role's keys.
    fn ec2(&self) -> io::Result<Expiring<Keys>> {
        let base = "http://169.254.169.254/latest";
        let client = self.metadata_client();
        let url = parse(&format!("{base}/api/token"))?;
        let ttl = "X-aws-ec2-metadata-token-ttl-seconds: 21600\r\n";
        let token = super::request(&url, &client, "PUT", ttl, &[])?;
        let token = String::from_utf8_lossy(&token.body).into_owned();
        let header = format!("X-aws-ec2-metadata-token: {token}\r\n");
        let roles =
            parse(&format!("{base}/meta-data/iam/security-credentials/"))?;
        let roles = super::request(&roles, &client, "GET", &header, &[])?;
        let roles = String::from_utf8_lossy(&roles.body).into_owned();
        let role = roles.lines().next().unwrap_or("").trim();
        if role.is_empty() {
            return Err(io::Error::other("no EC2 instance role"));
        }
        let url = format!("{base}/meta-data/iam/security-credentials/{role}");
        metadata_keys(&parse(&url)?, &client, &header)
    }

    fn web_identity(
        &self,
        file: &str,
        arn: &str,
    ) -> io::Result<Expiring<Keys>> {
        let token = fs::read_to_string(file)?;
        let session = env::var("AWS_ROLE_SESSION_NAME")
            .unwrap_or_else(|_| session_name());
        let query = [
            ("Action", "AssumeRoleWithWebIdentity"),
            ("RoleArn", arn),
            ("RoleSessionName", &session),
            ("WebIdentityToken", token.trim()),
        ];
        self.sts(&query.map(|(k, v)| (k.to_owned(), v.to_owned())), None)
    }

    fn assume(&self, role: &Role, base: &Keys) -> io::Result<Expiring<Keys>> {
        let session = match role.session_name.as_str() {
            "" => session_name(),
            name => name.to_owned(),
        };
        let mut form = vec![
            ("Action".to_owned(), "AssumeRole".to_owned()),
            ("RoleArn".into(), role.arn.clone()),
            ("RoleSessionName".into(), session),
        ];
        if !role.external_id.is_empty() {
            form.push(("ExternalId".into(), role.external_id.clone()));
        }
        for (i, (key, value)) in role.tags.iter().enumerate() {
            form.push((format!("Tags.member.{}.Key", i + 1), key.clone()));
            form.push((format!("Tags.member.{}.Value", i + 1), value.clone()));
        }
        self.sts(&form, Some(base))
    }

    /// An STS action posted as a form, signed with `signer` if given.
    fn sts(
        &self,
        form: &[(String, String)],
        signer: Option<&Keys>,
    ) -> io::Result<Expiring<Keys>> {
        let region = &self.settings.region;
        let host = match self.settings.fips {
            true => "sts-fips",
            false => "sts",
        };
        let suffix = match region.starts_with("cn-") {
            true => "amazonaws.com.cn",
            false => "amazonaws.com",
        };
        let url = parse(&format!("https://{host}.{region}.{suffix}/"))?;
        let mut pairs = form.to_vec();
        pairs.push(("Version".into(), STS_VERSION.into()));
        let body: Vec<String> = pairs
            .iter()
            .map(|(k, v)| format!("{}={}", query_escape(k), query_escape(v)))
            .collect();
        let body = body.join("&");
        let mut headers =
            "Content-Type: application/x-www-form-urlencoded; charset=utf-8\r\n"
                .to_owned();
        if let Some(keys) = signer {
            let request = Request {
                method: "POST",
                url: &url,
                headers: &headers,
                body: body.as_bytes(),
            };
            let now_s = time::now_ms() / 1000;
            headers.push_str(&signed(keys, region, "sts", &request, now_s));
        }
        let response = super::post(
            &url,
            &self.settings.client,
            &headers,
            body.as_bytes(),
        )?;
        let text = String::from_utf8_lossy(&response.body);
        if !response.ok() {
            let message = format!("sts: {} {}", response.status, text.trim());
            return Err(io::Error::other(message));
        }
        sts_keys(&text)
    }
}

fn parse(url: &str) -> io::Result<Url> {
    Url::parse(url).ok_or_else(|| io::Error::other(format!("url `{url}`")))
}

/// The v1 SDK's default session name: the time in nanoseconds.
fn session_name() -> String {
    time::now_ns().to_string()
}

fn from_env() -> Option<Keys> {
    let first = |names: &[&str]| {
        names
            .iter()
            .find_map(|n| env::var(n).ok().filter(|v| !v.is_empty()))
    };
    Some(Keys {
        id: first(&["AWS_ACCESS_KEY_ID", "AWS_ACCESS_KEY"])?,
        secret: first(&["AWS_SECRET_ACCESS_KEY", "AWS_SECRET_KEY"])?,
        token: first(&["AWS_SESSION_TOKEN"]).unwrap_or_default(),
    })
}

/// The shared credentials file's keys for `profile`.
// shortcut: profiles that name a role, SSO or a credential_process
// are not followed; add them when a host here uses one.
fn from_file(profile: &str) -> Option<Keys> {
    let path = shared_file("AWS_SHARED_CREDENTIALS_FILE", "credentials")?;
    let section = ini(&fs::read_to_string(path).ok()?, profile);
    let get = |key: &str| {
        let found = section.iter().find(|(k, _)| k == key);
        found.map(|(_, v)| v.clone())
    };
    let id = get("aws_access_key_id").filter(|v| !v.is_empty())?;
    Some(Keys {
        id,
        secret: get("aws_secret_access_key")?,
        token: get("aws_session_token").unwrap_or_default(),
    })
}

/// The region from the environment, else the shared config file.
fn region(profile: &str) -> String {
    let from_env = ["AWS_REGION", "AWS_DEFAULT_REGION"]
        .iter()
        .find_map(|n| env::var(n).ok().filter(|v| !v.is_empty()));
    if let Some(region) = from_env {
        return region;
    }
    let section = match profile {
        "default" => "default".to_owned(),
        name => format!("profile {name}"),
    };
    let text = shared_file("AWS_CONFIG_FILE", "config")
        .and_then(|path| fs::read_to_string(path).ok())
        .unwrap_or_default();
    let found = ini(&text, &section)
        .into_iter()
        .find(|(k, _)| k == "region");
    found.map(|(_, v)| v).unwrap_or_default()
}

fn shared_file(variable: &str, name: &str) -> Option<String> {
    env::var(variable).ok().or_else(|| {
        let home = env::var("HOME").ok()?;
        Some(format!("{home}/.aws/{name}"))
    })
}

/// The `key = value` lines of an INI file's `[section]`.
fn ini(text: &str, section: &str) -> Vec<(String, String)> {
    let mut inside = false;
    let mut found = Vec::new();
    for line in text.lines().map(str::trim) {
        if line.starts_with(['#', ';']) || line.is_empty() {
            continue;
        }
        if let Some(name) = line.strip_prefix('[') {
            inside = name.trim_end_matches(']').trim() == section;
        } else if let Some((key, value)) =
            line.split_once('=').filter(|_| inside)
        {
            found.push((key.trim().to_owned(), value.trim().to_owned()));
        }
    }
    found
}

/// ECS's credentials endpoint, and the header its token goes in.
fn container_url() -> Option<(Url, String)> {
    let header = env::var("AWS_CONTAINER_AUTHORIZATION_TOKEN")
        .map(|token| format!("Authorization: {token}\r\n"))
        .unwrap_or_default();
    let url = match env::var("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI") {
        Ok(path) => format!("http://169.254.170.2{path}"),
        Err(_) => env::var("AWS_CONTAINER_CREDENTIALS_FULL_URI").ok()?,
    };
    Some((Url::parse(&url)?, header))
}

/// Keys as ECS and EC2 give them: AccessKeyId, SecretAccessKey, Token,
/// Expiration.
fn metadata_keys(
    url: &Url,
    client: &Client,
    headers: &str,
) -> io::Result<Expiring<Keys>> {
    let response = super::request(url, client, "GET", headers, &[])?;
    let text = String::from_utf8_lossy(&response.body);
    let json = Json::parse(&text)
        .filter(|_| response.ok())
        .ok_or_else(|| io::Error::other(format!("metadata: {text}")))?;
    let get = |key| json.get(key).and_then(Json::str).unwrap_or("").to_owned();
    let keys = Keys {
        id: get("AccessKeyId"),
        secret: get("SecretAccessKey"),
        token: get("Token"),
    };
    Ok((keys, expiry(&get("Expiration"))))
}

/// The keys in an STS answer's Credentials.
fn sts_keys(xml: &str) -> io::Result<Expiring<Keys>> {
    let tag = |name: &str| {
        let open = format!("<{name}>");
        let start = xml.find(&open)? + open.len();
        let end = xml[start..].find(&format!("</{name}>"))? + start;
        Some(xml[start..end].trim().to_owned())
    };
    let id = tag("AccessKeyId")
        .ok_or_else(|| io::Error::other("sts: no AccessKeyId"))?;
    let keys = Keys {
        id,
        secret: tag("SecretAccessKey").unwrap_or_default(),
        token: tag("SessionToken").unwrap_or_default(),
    };
    Ok((keys, expiry(&tag("Expiration").unwrap_or_default())))
}

/// An RFC 3339 expiry as an instant.
fn expiry(text: &str) -> Option<Instant> {
    let at_ns = time::parse_rfc3339(text)?;
    let left = (at_ns - time::now_ns()).max(0) as u64;
    Some(Instant::now() + Duration::from_nanos(left))
}

/// The header lines that sign `request` at `now_s`: AWS's canonical
/// request over every header but Authorization and User-Agent, the
/// path cleaned as Prometheus cleans it.
fn signed(
    keys: &Keys,
    region: &str,
    service: &str,
    request: &Request,
    now_s: i64,
) -> String {
    let [y, mo, d, h, mi, s] = time::civil(now_s);
    let date = format!("{y:04}{mo:02}{d:02}");
    let stamp = format!("{date}T{h:02}{mi:02}{s:02}Z");
    let mut extra = format!("X-Amz-Date: {stamp}\r\n");
    if !keys.token.is_empty() {
        extra.push_str(&format!("X-Amz-Security-Token: {}\r\n", keys.token));
    }
    let lines = format!("{}{extra}", request.headers);
    let (canonical, names) = canonical(request, &lines);
    let scope = format!("{date}/{region}/{service}/aws4_request");
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{stamp}\n{scope}\n{}",
        hex(&sha256(canonical.as_bytes()))
    );
    let mut key =
        hmac_sha256(format!("AWS4{}", keys.secret).as_bytes(), date.as_bytes());
    for part in [region, service, "aws4_request"] {
        key = hmac_sha256(&key, part.as_bytes());
    }
    let signature = hex(&hmac_sha256(&key, to_sign.as_bytes()));
    format!(
        "{extra}Authorization: AWS4-HMAC-SHA256 Credential={}/{scope}, \
         SignedHeaders={names}, Signature={signature}\r\n",
        keys.id
    )
}

/// The canonical request and its signed headers' names.
fn canonical(request: &Request, lines: &str) -> (String, String) {
    let mut headers = vec![("host".to_owned(), request.url.host.clone())];
    for line in lines.split("\r\n") {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        if matches!(name.as_str(), "authorization" | "user-agent") {
            continue;
        }
        let value = value.split_whitespace().collect::<Vec<_>>().join(" ");
        headers.push((name, value));
    }
    headers.sort();
    let names: Vec<&str> = headers.iter().map(|(n, _)| n.as_str()).collect();
    let block: String =
        headers.iter().map(|(n, v)| format!("{n}:{v}\n")).collect();
    let (path, query) = request
        .url
        .path
        .split_once('?')
        .unwrap_or((&request.url.path, ""));
    let uri: String = crate::glob::clean(path)
        .split('/')
        .map(uri_escape)
        .collect::<Vec<_>>()
        .join("/");
    let canonical = format!(
        "{}\n{uri}\n{}\n{block}\n{}\n{}",
        request.method,
        canonical_query(query),
        names.join(";"),
        hex(&sha256(request.body)),
    );
    (canonical, names.join(";"))
}

fn canonical_query(query: &str) -> String {
    let mut pairs: Vec<(String, String)> = query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            let decode =
                |s: &str| unescape(s, true).unwrap_or_else(|| s.into());
            (uri_escape(&decode(key)), uri_escape(&decode(value)))
        })
        .collect();
    pairs.sort();
    let pairs: Vec<String> =
        pairs.iter().map(|(k, v)| format!("{k}={v}")).collect();
    pairs.join("&")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// AWS's get-vanilla-query-order-key-case example of the SigV4 test
    /// suite.
    #[test]
    fn signs_as_aws() {
        let keys = Keys {
            id: "AKIDEXAMPLE".into(),
            secret: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".into(),
            token: String::new(),
        };
        let url = Url::parse(
            "http://example.amazonaws.com/?Param2=value2&Param1=value1",
        )
        .unwrap();
        let request = Request {
            method: "GET",
            url: &url,
            headers: "",
            body: &[],
        };
        let at = time::parse_rfc3339("2015-08-30T12:36:00Z").unwrap();
        let lines =
            signed(&keys, "us-east-1", "service", &request, at / 1_000_000_000);
        assert!(lines.contains("SignedHeaders=host;x-amz-date, "));
        assert!(lines.ends_with(
            "Signature=b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500\r\n"
        ));
        let text = "[default]\nregion = x\n[profile p]\n; c\nregion = eu\n";
        assert_eq!(ini(text, "profile p"), [("region".into(), "eu".into())]);
    }
}
