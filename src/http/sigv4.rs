//! AWS Signature Version 4, as Prometheus's sigv4 (AWS SDK v2) signs
//! remote writes: keys from the configuration, else the SDK's chain
//! (environment, web identity, the shared profile with its source
//! profiles, roles, SSO and credential_process, ECS, EC2's metadata),
//! maybe swapped for a role's through STS AssumeRole.

use super::auth::{Expiring, Request};
use super::aws_profile::{self, Profile};
use super::{Client, Url};
use crate::digest::{hex, hmac_sha256, sha256};
use crate::encoding::{query_escape, unescape, uri_escape};
use crate::json::Json;
use crate::time;
use std::collections::hash_map::RandomState;
use std::env;
use std::fs;
use std::hash::{BuildHasher, Hasher};
use std::io;
use std::net::{IpAddr, ToSocketAddrs};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// sigv4's credentials cache: keys are asked for again up to this
/// long before they expire, less up to this share of it at random.
const EARLY: Duration = Duration::from_secs(30);
const JITTER: f64 = 0.5;
/// AssumeRole's DurationSeconds unless a profile asks for more.
pub const ROLE_SECONDS: u64 = 15 * 60;
/// Headers left unsigned: the SDK's IgnoredHeaders, sigv4's denylist,
/// and content-length, signed from the body instead.
const UNSIGNED: [&str; 7] = [
    "authorization",
    "user-agent",
    "x-amzn-trace-id",
    "expect",
    "transfer-encoding",
    "uber-trace-id",
    "content-length",
];
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
    pub duration_s: u64,
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
    /// The shared profile, if the files have it.
    profile: Option<Profile>,
    /// Whether the configuration named the profile: then it is used
    /// before the environment's keys.
    explicit: bool,
    kept: Mutex<Option<Expiring<Keys>>>,
}

impl SigV4 {
    /// Refused as Prometheus refuses it: when the shared files cannot
    /// be used, no keys can be found now, or there is no region.
    pub fn new(mut settings: Settings) -> Result<SigV4, String> {
        let explicit = !settings.profile.is_empty();
        if !explicit {
            let named = ["AWS_PROFILE", "AWS_DEFAULT_PROFILE"]
                .iter()
                .find_map(|n| env::var(n).ok().filter(|v| !v.is_empty()));
            settings.profile = named.unwrap_or_else(|| "default".into());
        }
        let profile = aws_profile::load(&settings.profile)
            .map_err(|e| format!("could not create new AWS session: {e}"))?;
        if settings.region.is_empty() {
            let from_env = ["AWS_REGION", "AWS_DEFAULT_REGION"]
                .iter()
                .find_map(|n| env::var(n).ok().filter(|v| !v.is_empty()));
            let shared = profile.as_ref().map(|p| p.region.clone());
            settings.region = from_env.or(shared).unwrap_or_default();
        }
        if settings.service.is_empty() {
            settings.service = "aps".into();
        }
        let sigv4 = SigV4 {
            settings,
            profile,
            explicit,
            kept: Mutex::new(None),
        };
        sigv4
            .base()
            .map_err(|e| format!("could not get SigV4 credentials: {e}"))?;
        if sigv4.settings.region.is_empty() {
            return Err("region not configured in sigv4 or in default \
                credentials chain"
                .into());
        }
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
            if expiry.is_none_or(|at| Instant::now() < at) {
                return Ok(keys.clone());
            }
        }
        let base = self.base()?;
        let (keys, expiry) = match &self.settings.role {
            None => base,
            Some(role) => self.assume(role, &base.0)?,
        };
        let refresh = expiry.map(|at| at.checked_sub(early()).unwrap_or(at));
        *kept = Some((keys.clone(), refresh));
        Ok(keys)
    }

    /// The SDK's resolveCredentialChain.
    fn base(&self) -> io::Result<Expiring<Keys>> {
        if let Some(keys) = &self.settings.keys {
            return Ok((keys.clone(), None));
        }
        if !self.explicit {
            if let Some(keys) = from_env() {
                return Ok((keys, None));
            }
            let file = env::var("AWS_WEB_IDENTITY_TOKEN_FILE").ok();
            if let Some(file) = file.filter(|f| !f.is_empty()) {
                let var = |n| env::var(n).unwrap_or_default();
                let (arn, name) =
                    (var("AWS_ROLE_ARN"), var("AWS_ROLE_SESSION_NAME"));
                return self.web_identity(&file, &arn, &name);
            }
        }
        self.profile_keys(self.profile.as_ref())
    }

    /// The SDK's resolveCredsFromProfile: the first source the profile
    /// names, then its role if it has one.
    fn profile_keys(
        &self,
        profile: Option<&Profile>,
    ) -> io::Result<Expiring<Keys>> {
        let Some(p) = profile else {
            return self.container_or_ec2();
        };
        let base = if let Some(source) = &p.source {
            self.profile_keys(Some(source))?
        } else if let Some(keys) = &p.keys {
            (keys.clone(), None)
        } else if !p.credential_source.is_empty() {
            self.named_source(&p.credential_source)?
        } else if !p.web_identity_file.is_empty() {
            let (file, arn) = (&p.web_identity_file, &p.role_arn);
            return self.web_identity(file, arn, &p.session_name);
        } else if p.sso.configured() {
            aws_profile::sso_keys(&p.sso, &self.settings.client)?
        } else if !p.login_session.is_empty() {
            let s = &self.settings;
            aws_profile::login_keys(&p.login_session, &s.region, &s.client)?
        } else if !p.credential_process.is_empty() {
            aws_profile::process_keys(&p.credential_process)?
        } else {
            self.container_or_ec2()?
        };
        match p.role_arn.is_empty() {
            true => Ok(base),
            false => self.assume(&profile_role(p), &base.0),
        }
    }

    /// credential_source: Environment, Ec2InstanceMetadata or
    /// EcsContainer, checked when the profile was read.
    fn named_source(&self, source: &str) -> io::Result<Expiring<Keys>> {
        match source {
            "Environment" => {
                from_env().map(|keys| (keys, None)).ok_or_else(|| {
                    io::Error::other("static credentials are empty")
                })
            }
            "Ec2InstanceMetadata" => self.ec2(),
            _ => self.container().unwrap_or_else(|| {
                Err(io::Error::other(
                    "EcsContainer was specified as the credential_source, \
                     but neither 'AWS_CONTAINER_CREDENTIALS_RELATIVE_URI' or \
                     AWS_CONTAINER_CREDENTIALS_FULL_URI' was set",
                ))
            }),
        }
    }

    fn container_or_ec2(&self) -> io::Result<Expiring<Keys>> {
        self.container().unwrap_or_else(|| self.ec2())
    }

    /// ECS's or EKS's credentials endpoint, if the environment names
    /// one; a full URI over plain HTTP only to loopback or their hosts.
    fn container(&self) -> Option<io::Result<Expiring<Keys>>> {
        let var = |name| env::var(name).ok().filter(|v: &String| !v.is_empty());
        let url = match var("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI") {
            Some(path) => format!("http://169.254.170.2{path}"),
            None => var("AWS_CONTAINER_CREDENTIALS_FULL_URI")?,
        };
        let token = match var("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE") {
            Some(file) => fs::read_to_string(&file).map_err(|e| {
                io::Error::other(format!(
                    "failed to read authorization token from {file}: {e}"
                ))
            }),
            None => {
                Ok(var("AWS_CONTAINER_AUTHORIZATION_TOKEN").unwrap_or_default())
            }
        };
        Some(token.and_then(|token| {
            let url = parse(&url)?;
            if !url.tls && !allowed_host(&url.name) {
                let message = format!(
                    "invalid endpoint host, {:?}, only loopback/ecs/eks \
                     hosts are allowed",
                    url.host
                );
                return Err(io::Error::other(message));
            }
            let mut headers = "Accept: application/json\r\n".to_owned();
            if !token.is_empty() {
                headers.push_str(&format!("Authorization: {token}\r\n"));
            }
            metadata_keys(&url, &self.metadata_client(), &headers)
        }))
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
        session: &str,
    ) -> io::Result<Expiring<Keys>> {
        let token = fs::read_to_string(file).map_err(|e| {
            io::Error::other(format!(
                "failed to retrieve jwt from provide source, {e}"
            ))
        })?;
        let session = match session {
            "" => time::now_ns().to_string(),
            name => name.to_owned(),
        };
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
            "" => format!("aws-go-sdk-{}", time::now_ns()),
            name => name.to_owned(),
        };
        let mut form = vec![
            ("Action".to_owned(), "AssumeRole".to_owned()),
            ("RoleArn".into(), role.arn.clone()),
            ("RoleSessionName".into(), session),
            ("DurationSeconds".into(), role.duration_s.to_string()),
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
        if region.is_empty() {
            let message = "Invalid Configuration: Missing Region";
            return Err(io::Error::other(message));
        }
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

/// Whether a plain-HTTP container endpoint may be used: loopback, or
/// ECS's or EKS's address, every address a name has.
fn allowed_host(host: &str) -> bool {
    let allowed = |ip: IpAddr| {
        ip.is_loopback()
            || ip == IpAddr::from([169, 254, 170, 2])
            || ip == IpAddr::from([169, 254, 170, 23])
            || ip == IpAddr::from([0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x23])
    };
    if let Ok(ip) = host.parse() {
        return allowed(ip);
    }
    match (host, 0).to_socket_addrs() {
        Ok(addrs) => {
            let ips: Vec<IpAddr> = addrs.map(|a| a.ip()).collect();
            !ips.is_empty() && ips.into_iter().all(allowed)
        }
        Err(_) => false,
    }
}

/// An RFC 3339 expiry as an instant.
/// A profile's role_arn and its options.
fn profile_role(p: &Profile) -> Role {
    Role {
        arn: p.role_arn.clone(),
        external_id: p.external_id.clone(),
        session_name: p.session_name.clone(),
        tags: Vec::new(),
        // As the SDK: a duration of 15 minutes or less is ignored.
        duration_s: p
            .duration_s
            .filter(|s| s / 60 > 15)
            .unwrap_or(ROLE_SECONDS),
    }
}

/// How long before they expire keys are fetched again: the SDK's
/// cache window less a random part of it, so agents started together
/// do not ask together.
fn early() -> Duration {
    // Random enough to spread agents out; not for secrets.
    let random = RandomState::new().build_hasher().finish();
    let fraction = random as f64 / u64::MAX as f64 * JITTER;
    EARLY.mul_f64(1.0 - fraction)
}

pub fn expiry(text: &str) -> Option<Instant> {
    let at_ns = time::parse_rfc3339(text)?;
    let left = (at_ns - time::now_ns()).max(0) as u64;
    Some(Instant::now() + Duration::from_nanos(left))
}

/// The header lines that sign `request` at `now_s`: AWS's canonical
/// request over every header but the UNSIGNED ones, the path cleaned
/// as Prometheus cleans it, then escaped again as the SDK's signer does.
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
    if !request.body.is_empty() {
        let length = request.body.len().to_string();
        headers.push(("content-length".to_owned(), length));
    }
    for line in lines.split("\r\n") {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        if UNSIGNED.contains(&name.as_str()) {
            continue;
        }
        let value = value.split_whitespace().collect::<Vec<_>>().join(" ");
        // A repeated header is signed once, its values joined by commas.
        match headers.iter_mut().find(|(n, _)| *n == name) {
            Some((_, values)) => *values = format!("{values},{value}"),
            None => headers.push((name, value)),
        }
    }
    headers.sort();
    let names: Vec<&str> = headers.iter().map(|(n, _)| n.as_str()).collect();
    let block: String =
        headers.iter().map(|(n, v)| format!("{n}:{v}\n")).collect();
    let path = &request.url.path;
    let (path, query) = path.split_once('?').unwrap_or((path, ""));
    let canonical = format!(
        "{}\n{}\n{}\n{block}\n{}\n{}",
        request.method,
        canonical_uri(path),
        canonical_query(query),
        names.join(";"),
        hex(&sha256(request.body)),
    );
    (canonical, names.join(";"))
}

fn canonical_uri(path: &str) -> String {
    let parts = crate::glob::clean(path);
    let parts: Vec<String> = parts.split('/').map(uri_escape).collect();
    parts.join("/")
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
    fn refreshes_early_at_random() {
        let range = Duration::from_secs(15)..=EARLY;
        let found: Vec<Duration> = (0..20).map(|_| early()).collect();
        assert!(found.iter().all(|e| range.contains(e)), "{found:?}");
        assert!(found.windows(2).any(|w| w[0] != w[1]));
    }

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
        let posted = Request {
            method: "POST",
            headers: "X-A: 1\r\nX-A: 2\r\nUser-Agent: u\r\n",
            body: b"data",
            ..request
        };
        let lines = signed(&keys, "r", "s", &posted, 0);
        let names = "SignedHeaders=content-length;host;x-a;x-amz-date,";
        assert!(lines.contains(names), "{lines}");
    }
}
