//! The AWS SDK v2's shared configuration, as Prometheus's sigv4 loads
//! it: `~/.aws/config` and `~/.aws/credentials` (or AWS_CONFIG_FILE,
//! AWS_SHARED_CREDENTIALS_FILE), the credentials file winning, a
//! profile resolved through its source profiles; and the credentials
//! only a profile can name: SSO and credential_process.

use super::auth::Expiring;
use super::sigv4::{Keys, expiry};
use super::{Client, Url};
use crate::digest::{hex, sha1};
use crate::encoding::query_escape;
use crate::json::Json;
use crate::time;
use std::env;
use std::fs;
use std::io::{self, Read};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// credential_process may run this long, as the SDK's DefaultTimeout.
const PROCESS_TIMEOUT: Duration = Duration::from_secs(60);

/// An INI section; `error` refuses the profile when it is used.
struct Section {
    name: String,
    values: Vec<(String, String)>,
    error: Option<String>,
}

impl Section {
    fn get(&self, key: &str) -> String {
        let found = self.values.iter().rev().find(|(k, _)| k == key);
        found.map(|(_, v)| v.clone()).unwrap_or_default()
    }

    fn has(&self, key: &str) -> bool {
        self.values.iter().any(|(k, _)| k == key)
    }
}

/// A profile as the SDK's SharedConfig holds it; empty strings unset.
#[derive(Default)]
pub struct Profile {
    pub name: String,
    pub keys: Option<Keys>,
    pub region: String,
    pub role_arn: String,
    pub external_id: String,
    pub session_name: String,
    mfa_serial: String,
    /// duration_seconds, when set.
    pub duration_s: Option<u64>,
    source_name: String,
    pub source: Option<Box<Profile>>,
    pub credential_source: String,
    pub credential_process: String,
    pub web_identity_file: String,
    pub sso: Sso,
    pub login_session: String,
}

/// SSO's settings; with `session`, its section's region and start URL.
#[derive(Default)]
pub struct Sso {
    pub session: String,
    pub start_url: String,
    pub region: String,
    pub account_id: String,
    pub role_name: String,
}

impl Sso {
    fn legacy(&self) -> bool {
        [
            &self.start_url,
            &self.region,
            &self.account_id,
            &self.role_name,
        ]
        .iter()
        .any(|v| !v.is_empty())
    }

    pub fn configured(&self) -> bool {
        !self.session.is_empty() || self.legacy()
    }
}

/// The named profile, resolved and checked; None when no file has it,
/// as the SDK then goes on without one.
pub fn load(name: &str) -> Result<Option<Profile>, String> {
    let sections = merged();
    if !sections.iter().any(|s| s.name == name) {
        return Ok(None);
    }
    let profile = resolve(&sections, name, &mut Vec::new())?;
    profile.check()?;
    Ok(Some(profile))
}

fn shared_file(variable: &str, name: &str) -> String {
    let home = env::var("HOME").unwrap_or_default();
    let path =
        env::var(variable).unwrap_or_else(|_| format!("{home}/.aws/{name}"));
    fs::read_to_string(path).unwrap_or_default()
}

/// Both files' sections: the config file's `[profile x]` as `x` (an
/// unprefixed one other than default is ignored there), the credentials
/// file's over them key by key, its keys only as a pair.
fn merged() -> Vec<Section> {
    let mut merged: Vec<Section> = Vec::new();
    for mut section in sections(&shared_file("AWS_CONFIG_FILE", "config")) {
        if let Some(name) = section.name.strip_prefix("profile ") {
            section.name = name.trim().to_owned();
            merged.retain(|s| s.name != section.name);
        } else if section.name != "default"
            && !section.name.starts_with("sso-session ")
            || merged.iter().any(|s| s.name == section.name)
        {
            continue;
        }
        merged.push(paired(section));
    }
    let credentials = shared_file("AWS_SHARED_CREDENTIALS_FILE", "credentials");
    for section in sections(&credentials) {
        if section.name.starts_with("profile ") {
            continue;
        }
        let section = paired(section);
        match merged.iter_mut().find(|s| s.name == section.name) {
            Some(into) => merge(into, section),
            None => merged.push(section),
        }
    }
    merged
}

/// The section, refused when it has one key of the pair only.
fn paired(mut section: Section) -> Section {
    if section.has("aws_access_key_id") != section.has("aws_secret_access_key")
    {
        let name = &section.name;
        section.error = Some(format!("partial credentials found for {name}"));
    }
    section
}

fn merge(into: &mut Section, from: Section) {
    into.error = from.error.clone();
    let pair = from.has("aws_access_key_id") && from.error.is_none();
    let keys = ["aws_access_key_id", "aws_secret_access_key"];
    for (key, value) in from.values {
        let key_only =
            keys.contains(&key.as_str()) || key == "aws_session_token";
        if !key_only || pair {
            into.values.push((key, value));
        }
    }
}

/// An AWS INI file's sections; indented lines under a key without a
/// value are its sub-properties (as `s3 =`), not the profile's.
fn sections(text: &str) -> Vec<Section> {
    let mut found: Vec<Section> = Vec::new();
    let mut nested = false;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with(['#', ';']) {
            continue;
        }
        if let Some(name) = line.strip_prefix('[') {
            let name = name.trim_end_matches(']').split_whitespace();
            let values = Vec::new();
            let name = name.collect::<Vec<_>>().join(" ");
            found.push(Section {
                name,
                values,
                error: None,
            });
            nested = false;
            continue;
        }
        let indented = raw.starts_with([' ', '\t']);
        let (Some((key, value)), Some(section)) =
            (line.split_once('='), found.last_mut())
        else {
            continue;
        };
        if indented && nested {
            continue;
        }
        let (key, value) = (key.trim().to_owned(), value.trim().to_owned());
        nested = value.is_empty();
        section.values.push((key, value));
    }
    found
}

/// The SDK's setFromIniSections: `seen` holds the profiles already on
/// the chain, so a profile that is its own source uses its own keys.
fn resolve(
    sections: &[Section],
    name: &str,
    seen: &mut Vec<String>,
) -> Result<Profile, String> {
    let section = sections.iter().find(|s| s.name == name);
    let section = section.ok_or_else(|| missing(name))?;
    if let Some(error) = &section.error {
        return Err(format!(
            "error fetching config from profile, {name}, Error using \
             profile: \n 1, {error}\n"
        ));
    }
    let mut profile = Profile::from(section);
    if seen.iter().any(|s| s == name) {
        profile.clear_role();
    } else {
        profile.requires_arn()?;
    }
    if !seen.is_empty() && profile.keys.is_some() {
        return Ok(profile);
    }
    seen.push(name.to_owned());
    profile.one_type()?;
    if !profile.source_name.is_empty() {
        profile.clear_credentials();
        profile.source = Some(Box::new(source(sections, &profile, seen)?));
    }
    if !profile.sso.session.is_empty() {
        sso_session(sections, &mut profile)?;
    }
    Ok(profile)
}

fn missing(name: &str) -> String {
    format!("failed to get shared config profile, {name}")
}

fn source(
    sections: &[Section],
    profile: &Profile,
    seen: &mut Vec<String>,
) -> Result<Profile, String> {
    let name = &profile.source_name;
    let assume = |error: &str| {
        let arn = &profile.role_arn;
        format!("failed to load assume role {arn}, of profile {name}, {error}")
    };
    if !sections.iter().any(|s| &s.name == name) {
        return Err(assume(&missing(name)));
    }
    let found = resolve(sections, name, seen)?;
    if !found.has_credentials() {
        return Err(assume("<nil>"));
    }
    Ok(found)
}

/// The profile's SSO settings checked against its sso-session's.
fn sso_session(
    sections: &[Section],
    profile: &mut Profile,
) -> Result<(), String> {
    let session = profile.sso.session.trim();
    let wanted = format!("sso-session {session}");
    let section = sections.iter().find(|s| s.name == wanted);
    let section = section.ok_or_else(|| {
        format!(
            "failed to find SSO session section, {}",
            profile.sso.session
        )
    })?;
    let name = &profile.name;
    for key in ["sso_region", "sso_start_url"] {
        let value = section.get(key);
        let own = match key {
            "sso_region" => &mut profile.sso.region,
            _ => &mut profile.sso.start_url,
        };
        if value.is_empty() {
            return Err(format!(
                "profile {name:?} is configured to use SSO but is missing \
                 required configuration: {key}"
            ));
        }
        if !own.is_empty() && *own != value {
            return Err(format!(
                "{key} in profile {name:?} must match {key} in sso-session"
            ));
        }
        *own = value;
    }
    Ok(())
}

impl Profile {
    fn from(section: &Section) -> Profile {
        let get = |key| section.get(key);
        let (id, secret) =
            (get("aws_access_key_id"), get("aws_secret_access_key"));
        let keys = (!id.is_empty() && !secret.is_empty()).then(|| Keys {
            id,
            secret,
            token: get("aws_session_token"),
        });
        let duration_s = section
            .has("duration_seconds")
            .then(|| get("duration_seconds").parse().unwrap_or(0));
        Profile {
            name: section.name.clone(),
            keys,
            region: get("region"),
            role_arn: get("role_arn"),
            external_id: get("external_id"),
            session_name: get("role_session_name"),
            mfa_serial: get("mfa_serial"),
            duration_s,
            source_name: get("source_profile"),
            source: None,
            credential_source: get("credential_source"),
            credential_process: get("credential_process"),
            web_identity_file: get("web_identity_token_file"),
            sso: Sso {
                session: get("sso_session"),
                start_url: get("sso_start_url"),
                region: get("sso_region"),
                account_id: get("sso_account_id"),
                role_name: get("sso_role_name"),
            },
            login_session: get("login_session"),
        }
    }

    fn clear_role(&mut self) {
        self.role_arn.clear();
        self.external_id.clear();
        self.mfa_serial.clear();
        self.session_name.clear();
        self.source_name.clear();
    }

    fn clear_credentials(&mut self) {
        self.credential_source.clear();
        self.credential_process.clear();
        self.web_identity_file.clear();
        self.keys = None;
        let sso = &mut self.sso;
        for value in [&mut sso.account_id, &mut sso.region] {
            value.clear();
        }
        sso.role_name.clear();
        sso.start_url.clear();
    }

    fn requires_arn(&self) -> Result<(), String> {
        let kind = [
            ("source_profile", &self.source_name),
            ("credential_source", &self.credential_source),
            ("web_identity_token_file", &self.web_identity_file),
        ]
        .into_iter()
        .find(|(_, v)| !v.is_empty());
        match kind {
            Some((kind, _)) if self.role_arn.is_empty() => Err(format!(
                "credential type {kind} requires role_arn, profile {}",
                self.name
            )),
            _ => Ok(()),
        }
    }

    fn one_type(&self) -> Result<(), String> {
        let set = [
            &self.source_name,
            &self.credential_source,
            &self.credential_process,
            &self.web_identity_file,
        ];
        if set.iter().filter(|v| !v.is_empty()).count() > 1 {
            return Err("only one credential type may be specified per \
                profile: source profile, credential source, credential \
                process, web identity token"
                .into());
        }
        Ok(())
    }

    fn has_credentials(&self) -> bool {
        let named = [
            &self.source_name,
            &self.credential_source,
            &self.credential_process,
            &self.web_identity_file,
        ];
        named.iter().any(|v| !v.is_empty())
            || self.sso.configured()
            || self.keys.is_some()
    }

    /// What the SDK refuses while it loads, before any credentials are
    /// asked for: along the branch resolveCredsFromProfile takes.
    fn check(&self) -> Result<(), String> {
        if let Some(source) = &self.source {
            source.check()?;
        } else if self.keys.is_some() {
        } else if !self.credential_source.is_empty() {
            let known = ["EcsContainer", "Ec2InstanceMetadata", "Environment"];
            if !known.contains(&self.credential_source.as_str()) {
                return Err("credential_source values must be EcsContainer, \
                    Ec2InstanceMetadata, or Environment"
                    .into());
            }
        } else if !self.web_identity_file.is_empty() {
            return Ok(());
        } else if self.sso.configured() {
            self.check_sso()?;
        } else if !self.login_session.is_empty() && cfg!(not(feature = "tls")) {
            return Err(format!(
                "profile {}: login_session needs feature tls",
                self.name
            ));
        }
        if !self.role_arn.is_empty() && !self.mfa_serial.is_empty() {
            return Err("assume role with MFA enabled, but \
                AssumeRoleTokenProvider session option not set."
                .into());
        }
        Ok(())
    }

    fn check_sso(&self) -> Result<(), String> {
        let sso = &self.sso;
        let mut wanted = vec![("sso_account_id", &sso.account_id)];
        wanted.push(("sso_role_name", &sso.role_name));
        if sso.session.is_empty() {
            wanted.insert(0, ("sso_start_url", &sso.start_url));
            wanted.insert(0, ("sso_region", &sso.region));
        }
        let missing: Vec<&str> = wanted
            .iter()
            .filter(|(_, v)| v.is_empty())
            .map(|(k, _)| *k)
            .collect();
        if missing.is_empty() {
            return Ok(());
        }
        Err(format!(
            "profile {:?} is configured to use SSO but is missing required \
             configuration: {}",
            self.name,
            missing.join(", ")
        ))
    }
}

/// SSO's role keys: the token the AWS CLI cached at sign-in (refreshed
/// through SSO OIDC when an sso-session's has expired), then the
/// portal's GetRoleCredentials.
pub fn sso_keys(sso: &Sso, client: &Client) -> io::Result<Expiring<Keys>> {
    let access = access_token(sso, client)?;
    let url = format!(
        "https://portal.sso.{}.amazonaws.com/federation/credentials\
         ?account_id={}&role_name={}",
        sso.region,
        query_escape(&sso.account_id),
        query_escape(&sso.role_name)
    );
    let url = Url::parse(&url).ok_or_else(|| io::Error::other(url.clone()))?;
    let header = format!("x-amz-sso_bearer_token: {access}\r\n");
    let response = super::request(&url, client, "GET", &header, &[])?;
    let text = String::from_utf8_lossy(&response.body);
    let json = Json::parse(&text).filter(|_| response.ok());
    let json = json.ok_or_else(|| io::Error::other(format!("sso: {text}")))?;
    let found = json.get("roleCredentials");
    let get = |key| found.and_then(|c| c.get(key));
    let text = |key| get(key).and_then(Json::str).unwrap_or("").to_owned();
    let keys = Keys {
        id: text("accessKeyId"),
        secret: text("secretAccessKey"),
        token: text("sessionToken"),
    };
    let at_ms = get("expiration").and_then(Json::num).unwrap_or(0.0) as i64;
    let left_ms = (at_ms - time::now_ms()).max(0) as u64;
    Ok((keys, Some(Instant::now() + Duration::from_millis(left_ms))))
}

/// The access token cached at sign-in, refreshed if need be.
fn access_token(sso: &Sso, client: &Client) -> io::Result<String> {
    let key = match sso.session.as_str() {
        "" => &sso.start_url,
        session => session,
    };
    let home = env::var("HOME").unwrap_or_default();
    let file =
        format!("{home}/.aws/sso/cache/{}.json", hex(&sha1(key.as_bytes())));
    let mut token = cached_token(&file)?;
    if sso_expiry(&token).is_none_or(|at| at <= time::now_ns()) {
        if sso.session.is_empty() {
            let message = "the SSO session has expired or is invalid";
            return Err(io::Error::other(message));
        }
        token = refreshed(&file, token, &sso.region, client)?;
    }
    let access = token.get("accessToken").and_then(Json::str);
    Ok(access.unwrap_or("").to_owned())
}

fn cached_token(file: &str) -> io::Result<Json> {
    let text = fs::read_to_string(file)?;
    let token = Json::parse(&text).unwrap_or(Json::Null);
    let access = token.get("accessToken").and_then(Json::str);
    if access.is_none_or(str::is_empty) || sso_expiry(&token).is_none() {
        let message =
            "cached SSO token must contain accessToken and expiresAt fields";
        return Err(io::Error::other(message));
    }
    Ok(token)
}

fn sso_expiry(token: &Json) -> Option<i64> {
    time::parse_rfc3339(token.get("expiresAt")?.str()?)
}

/// SSO OIDC's refresh_token grant; the new token is written back to
/// the cache with the fields the SDK does not know kept.
fn refreshed(
    file: &str,
    token: Json,
    region: &str,
    client: &Client,
) -> io::Result<Json> {
    let field = |key| token.get(key).and_then(Json::str).unwrap_or("");
    let given = ["clientId", "clientSecret", "refreshToken"].map(field);
    if given.iter().any(|v| v.is_empty()) {
        let message = "cached SSO token is expired, or not present, and \
            cannot be refreshed";
        return Err(io::Error::other(message));
    }
    let text = |s: &str| Json::Str(s.to_owned());
    let body = Json::Obj(vec![
        ("clientId".into(), text(given[0])),
        ("clientSecret".into(), text(given[1])),
        ("grantType".into(), text("refresh_token")),
        ("refreshToken".into(), text(given[2])),
    ]);
    let url = format!("https://oidc.{region}.amazonaws.com/token");
    let url = Url::parse(&url).ok_or_else(|| io::Error::other(url.clone()))?;
    let header = "Content-Type: application/json\r\n";
    let body = body.go_text();
    let response = super::post(&url, client, header, body.as_bytes())?;
    let answer = String::from_utf8_lossy(&response.body);
    let json = Json::parse(&answer).filter(|_| response.ok());
    let json = json.ok_or_else(|| {
        io::Error::other(format!("unable to refresh SSO token, {answer}"))
    })?;
    let token = updated(token, &json);
    fs::write(file, token.go_text())?;
    Ok(token)
}

/// The cached token with the refreshed one's fields, as the SDK writes
/// it back.
fn updated(token: Json, json: &Json) -> Json {
    let seconds = json.get("expiresIn").and_then(Json::num).unwrap_or(0.0);
    let at = time::rfc3339(time::now_ms() / 1000 + seconds as i64);
    let new = |key| json.get(key).and_then(Json::str).unwrap_or("");
    let mut fields = token.obj().to_vec();
    let updates = [
        ("accessToken", new("accessToken").to_owned()),
        ("expiresAt", at),
        ("refreshToken", new("refreshToken").to_owned()),
    ];
    for (key, value) in updates {
        fields.retain(|(k, _)| k != key);
        fields.push((key.to_owned(), Json::Str(value)));
    }
    Json::Obj(fields)
}

/// An `aws login` session's keys (refused when read without `tls`).
pub fn login_keys(
    session: &str,
    region: &str,
    client: &Client,
) -> io::Result<Expiring<Keys>> {
    #[cfg(feature = "tls")]
    return super::aws_login::keys(session, region, client);
    #[cfg(not(feature = "tls"))]
    {
        let _ = (session, region, client);
        Err(io::Error::other("login_session needs feature tls"))
    }
}

/// credential_process run by `sh -c`, its JSON answer read as the
/// SDK's processcreds reads it.
pub fn process_keys(command: &str) -> io::Result<Expiring<Keys>> {
    let mut child = Command::new("sh")
        .args(["-c", command])
        .stdout(Stdio::piped())
        .spawn()?;
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() > PROCESS_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::other("credential process timed out"));
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let mut out = String::new();
    if let Some(mut stdout) = child.stdout.take() {
        stdout.read_to_string(&mut out)?;
    }
    if !status.success() {
        let message = format!("error in credential_process: {status}");
        return Err(io::Error::other(message));
    }
    process_answer(&out)
}

fn process_answer(out: &str) -> io::Result<Expiring<Keys>> {
    let error = |message: String| Err(io::Error::other(message));
    let Some(json) = Json::parse(out) else {
        return error(format!("parse failed of process output: {out}"));
    };
    if json.get("Version").and_then(Json::num) != Some(1.0) {
        return error("wrong version in process output (not 1)".into());
    }
    let get = |key| json.get(key).and_then(Json::str).unwrap_or("");
    for key in ["AccessKeyId", "SecretAccessKey"] {
        if get(key).is_empty() {
            return error(format!("missing {key} in process output"));
        }
    }
    let keys = Keys {
        id: get("AccessKeyId").into(),
        secret: get("SecretAccessKey").into(),
        token: get("SessionToken").into(),
    };
    Ok((keys, expiry(get("Expiration"))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_profiles() {
        let config = "[default]\nregion = eu\n\
            [profile chain]\nrole_arn = arn:b\nsource_profile = base\n\
            [profile self]\nrole_arn = arn:s\nsource_profile = self\n\
            aws_access_key_id = SI\naws_secret_access_key = SS\n\
            [profile lone]\nsource_profile = base\n\
            [profile sso]\nsso_session = s\nsso_account_id = 1\n\
            sso_role_name = r\n[sso-session s]\nsso_region = us\n\
            sso_start_url = https://x\n[ignored]\nregion = no\n";
        let credentials = "[base]\naws_access_key_id = A\n\
            aws_secret_access_key = S\n[half]\naws_access_key_id = A\n";
        let dir =
            env::temp_dir().join(format!("ha-aws-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("config"), config).unwrap();
        fs::write(dir.join("credentials"), credentials).unwrap();
        // SAFETY: tests that read these variables run in this one only.
        unsafe {
            env::set_var("AWS_CONFIG_FILE", dir.join("config"));
            env::set_var(
                "AWS_SHARED_CREDENTIALS_FILE",
                dir.join("credentials"),
            );
        }
        let chain = load("chain").unwrap().unwrap();
        let source = chain.source.as_ref().unwrap();
        assert_eq!(source.keys.as_ref().unwrap().id, "A");
        let own = load("self").unwrap().unwrap();
        assert_eq!(own.source.unwrap().keys.unwrap().id, "SI");
        assert_eq!(load("default").unwrap().unwrap().region, "eu");
        assert!(load("ignored").unwrap().is_none());
        assert!(load("lone").err().unwrap().contains("requires role_arn"));
        assert!(load("half").err().unwrap().contains("partial"));
        let sso = load("sso").unwrap().unwrap().sso;
        assert_eq!((sso.region.as_str(), sso.account_id.as_str()), ("us", "1"));
        fs::remove_dir_all(dir).unwrap();
        let answer = r#"{"Version":1,"AccessKeyId":"a","SecretAccessKey":"s"}"#;
        assert_eq!(process_answer(answer).unwrap().0.id, "a");
        assert!(process_answer(r#"{"Version":2}"#).is_err());
    }
}
