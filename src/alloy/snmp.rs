//! prometheus.exporter.snmp: its targets, and the v2c communities of
//! its `config`'s `auths`, snmp_exporter's YAML; the modules are the
//! embedded ones (crate::snmp).

use super::compile::{Body, Plan};
use super::components::{built, internal_target, targets_value};
use super::value::Value;
use crate::relabel::Labels;

/// snmp_exporter's default auth.
const PUBLIC: (&str, &str) = ("public_v2", "public");

pub fn build(body: &Body, plan: &mut Plan) -> Result<Value, String> {
    built(body, "snmp", cfg!(feature = "snmp"))?;
    let attrs = ["config", "config_merge_strategy", "targets"];
    body.check(&attrs, &["target"])?;
    let pos = body.block.pos;
    let strategy = body.string_or("config_merge_strategy", "replace")?;
    if !["replace", "merge"].contains(&strategy.as_str()) {
        return Err(body.error(pos, "config_merge_strategy: replace or merge"));
    }
    let config = body.string_or("config", "")?;
    let mut auths = auths(&config).map_err(|e| body.error(pos, &e))?;
    auths.push((PUBLIC.0.into(), PUBLIC.1.into()));
    let (devices, exported) = devices(body, &targets(body)?, &auths)?;
    #[cfg(feature = "snmp")]
    {
        let snmp = crate::snmp::Snmp::new(devices, plan.print)
            .map_err(|e| body.error(pos, &e))?;
        let exporter = super::compile::Exporter::Snmp(snmp);
        plan.exporters.push((body.id.to_owned(), exporter));
    }
    #[cfg(not(feature = "snmp"))]
    let _ = (devices, plan);
    Ok(targets_value(exported))
}

/// The devices of the `targets` list and the `target` blocks.
fn targets(body: &Body) -> Result<Vec<Labels>, String> {
    let mut targets: Vec<Labels> = Vec::new();
    if let Some((value, pos)) = body.value("targets")? {
        let Value::Array(_) = value else {
            return Err(body.error(pos, "`targets` is a list of objects"));
        };
        let listed = super::compile::targets_of(value);
        if let crate::targets::Targets::Static(found) =
            listed.map_err(|e| body.error(pos, &e))?
        {
            targets = found;
        }
    }
    for block in body.blocks("target") {
        block.check(&["address", "module", "auth"], &[])?;
        let mut target = vec![("name".to_owned(), block.label().to_owned())];
        for key in ["address", "module", "auth"] {
            target.push((key.to_owned(), block.string_or(key, "")?));
        }
        targets.push(target);
    }
    Ok(targets)
}

#[cfg(not(feature = "snmp"))]
type Device = ();
#[cfg(feature = "snmp")]
use crate::snmp::Device;

/// Each target's device, and the target exported for its scrape.
fn devices(
    body: &Body,
    targets: &[Labels],
    auths: &Labels,
) -> Result<(Vec<Device>, Vec<Labels>), String> {
    let mut devices = Vec::new();
    let mut exported = Vec::new();
    for target in targets {
        let get = |key: &str| crate::targets::get(target, key).to_owned();
        let (name, address) = (get("name"), get("address"));
        let auth = Some(get("auth")).filter(|a| !a.is_empty());
        let auth = auth.unwrap_or_else(|| PUBLIC.0.to_owned());
        let community = auths.iter().find(|(a, _)| *a == auth);
        let Some((_, community)) = community else {
            let message = format!("{name}: no auth `{auth}` in config");
            return Err(body.error(body.block.pos, &message));
        };
        let module = Some(get("module")).filter(|m| !m.is_empty());
        let module = module.unwrap_or_else(|| "if_mib".to_owned());
        let mut labels = internal_target(body.id, "snmp");
        for (key, value) in [
            ("name", &name),
            ("target", &address),
            ("module", &module),
            ("auth", &auth),
        ] {
            labels.push((format!("__param_{key}"), value.clone()));
        }
        exported.push(labels);
        #[cfg(feature = "snmp")]
        devices.push(Device {
            name,
            address,
            community: community.clone(),
            modules: module.split(',').map(str::to_owned).collect(),
        });
        let _ = community;
    }
    Ok((devices, exported))
}

/// `auths:` from snmp_exporter's YAML: each name's v2c community.
fn auths(yaml: &str) -> Result<Labels, String> {
    let mut auths: Labels = Vec::new();
    for line in yaml.lines() {
        let text = line.trim();
        if text.is_empty() || text.starts_with('#') {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        let (key, value) =
            text.split_once(':').ok_or(format!("config: `{text}`"))?;
        let value = unquote(value.trim());
        match (indent, key, auths.last_mut()) {
            (0, "auths", _) => {}
            (0, other, _) => {
                return Err(format!("config: only `auths`, not `{other}`"));
            }
            (2, name, _) => auths.push((name.to_owned(), String::new())),
            (4, "community", Some(last)) => last.1 = value,
            (4, "version", _) if value == "2" => {}
            (_, other, _) => {
                return Err(format!("config: `{other}` (v2c only)"));
            }
        }
    }
    Ok(auths)
}

fn unquote(value: &str) -> String {
    if value.starts_with('"') {
        let json = crate::json::Json::parse(value);
        if let Some(text) = json.as_ref().and_then(crate::json::Json::str) {
            return text.to_owned();
        }
    }
    let single = value.strip_prefix('\'').and_then(|v| v.strip_suffix('\''));
    single.unwrap_or(value).replace("''", "'")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_auths() {
        let yaml =
            "auths:\n  router:\n    version: 2\n    community: \"a b\"\n";
        let found = auths(yaml).unwrap();
        assert_eq!(found, [("router".to_owned(), "a b".to_owned())]);
        assert!(auths("modules:\n  x: 1\n").is_err());
        assert!(auths("auths:\n  r:\n    version: 3\n").is_err());
    }
}
