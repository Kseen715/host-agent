//! Alloy's standard library, as v1.20.1 has it: `sys`, `convert`,
//! `string`, `encoding`, `array`, `file`, `coalesce`, `json_path`, and
//! the deprecated names that stand for some of them. YAML is not read.

use super::compile::targets_of;
use super::value::{Capsule, Value, equal};
use crate::encoding;
use crate::json::Json;
use crate::targets::{Targets, combine};
use crate::template::{Val, printf};

/// The deprecated names and the functions they stand for.
const DEPRECATED: [(&str, &str); 16] = [
    ("env", "sys.env"),
    ("nonsensitive", "convert.nonsensitive"),
    ("concat", "array.concat"),
    ("json_decode", "encoding.from_json"),
    ("yaml_decode", "encoding.from_yaml"),
    ("base64_decode", "encoding.from_base64"),
    ("format", "string.format"),
    ("join", "string.join"),
    ("replace", "string.replace"),
    ("split", "string.split"),
    ("to_lower", "string.to_lower"),
    ("to_upper", "string.to_upper"),
    ("trim", "string.trim"),
    ("trim_prefix", "string.trim_prefix"),
    ("trim_suffix", "string.trim_suffix"),
    ("trim_space", "string.trim_space"),
];

pub fn call(name: &str, args: Vec<Value>) -> Result<Value, String> {
    let name = DEPRECATED
        .iter()
        .find(|(old, _)| *old == name)
        .map_or(name, |(_, new)| new);
    match name.split_once('.') {
        Some(("string", function)) => string(function, &args),
        Some(("encoding", function)) => encode(function, &args),
        Some(("array", function)) => array(function, args),
        _ => other(name, args),
    }
}

fn unknown() -> Result<Value, String> {
    Err("not a function this agent has".into())
}

fn other(name: &str, args: Vec<Value>) -> Result<Value, String> {
    match name {
        "sys.env" => {
            let [key] = texts(&args)?;
            Ok(Value::String(std::env::var(key).unwrap_or_default()))
        }
        "convert.nonsensitive" => {
            let [secret] = texts(&args)?;
            Ok(Value::String(secret.to_owned()))
        }
        "coalesce" => Ok(coalesce(args)),
        "json_path" => {
            let [text, path] = texts(&args)?;
            json_path(text, path)
        }
        "file.path_join" => path_join(&args),
        _ => unknown(),
    }
}

/// Exactly `N` arguments, all strings.
fn texts<const N: usize>(args: &[Value]) -> Result<[&str; N], String> {
    let wrong = || format!("takes {N} string argument(s)");
    if args.len() != N {
        return Err(wrong());
    }
    let mut out = [""; N];
    for (slot, arg) in out.iter_mut().zip(args) {
        let Value::String(text) = arg else {
            return Err(wrong());
        };
        *slot = text;
    }
    Ok(out)
}

fn string(name: &str, args: &[Value]) -> Result<Value, String> {
    let text = |s: &str| Ok(Value::String(s.to_owned()));
    match name {
        "format" => format(args),
        "join" => join(args),
        "split" => {
            let [s, separator] = texts(args)?;
            Ok(split(s, separator))
        }
        "replace" => {
            let [s, old, new] = texts(args)?;
            text(&s.replace(old, new))
        }
        "to_lower" => text(&texts::<1>(args)?[0].to_lowercase()),
        "to_upper" => text(&texts::<1>(args)?[0].to_uppercase()),
        "trim" => {
            let [s, cutset] = texts(args)?;
            text(s.trim_matches(|c| cutset.contains(c)))
        }
        "trim_prefix" => {
            let [s, prefix] = texts(args)?;
            text(s.strip_prefix(prefix).unwrap_or(s))
        }
        "trim_suffix" => {
            let [s, suffix] = texts(args)?;
            text(s.strip_suffix(suffix).unwrap_or(s))
        }
        "trim_space" => text(texts::<1>(args)?[0].trim()),
        _ => unknown(),
    }
}

/// Go's fmt.Sprintf. Numbers here do not remember how they were
/// written: a whole one is an int to it (`%d`), any other a float.
fn format(args: &[Value]) -> Result<Value, String> {
    let Some((Value::String(format), rest)) = args.split_first() else {
        return Err("takes a format string first".into());
    };
    let values: Result<Vec<Val>, String> = rest
        .iter()
        .map(|value| {
            Ok(match value {
                Value::String(s) => Val::Str(s.clone()),
                Value::Number(n) if n.fract() == 0.0 => Val::Int(*n as i64),
                Value::Number(n) => Val::Float(*n),
                Value::Bool(b) => Val::Bool(*b),
                Value::Null => Val::Str("<nil>".into()),
                other => {
                    return Err(format!("cannot format a {}", other.kind()));
                }
            })
        })
        .collect();
    Ok(Value::String(printf(format, &values?)))
}

fn join(args: &[Value]) -> Result<Value, String> {
    let [Value::Array(items), Value::String(separator)] = args else {
        return Err("takes an array of strings and a string".into());
    };
    let words: Result<Vec<String>, String> = items
        .iter()
        .map(|item| match item {
            Value::String(s) => Ok(s.clone()),
            Value::Number(n) => Ok(n.to_string()),
            other => Err(format!("cannot join a {}", other.kind())),
        })
        .collect();
    Ok(Value::String(words?.join(separator)))
}

/// Go's strings.Split: an empty separator splits after each character.
fn split(text: &str, separator: &str) -> Value {
    let parts: Vec<Value> = match separator {
        "" => text.chars().map(|c| Value::String(c.into())).collect(),
        _ => text
            .split(separator)
            .map(|s| Value::String(s.into()))
            .collect(),
    };
    Value::Array(parts)
}

fn encode(name: &str, args: &[Value]) -> Result<Value, String> {
    let text = |s: String| Ok(Value::String(s));
    match name {
        "from_json" => {
            let json = Json::parse(texts::<1>(args)?[0]).ok_or("not JSON")?;
            Ok(from_json(&json))
        }
        "to_json" => text(to_json(args)?.go_text()),
        "from_base64" => decoded(texts(args)?, encoding::from_base64),
        "from_URLbase64" => decoded(texts(args)?, encoding::from_base64_url),
        "to_base64" => text(encoding::base64(texts::<1>(args)?[0].as_bytes())),
        "to_URLbase64" => {
            text(encoding::base64_url(texts::<1>(args)?[0].as_bytes()))
        }
        "url_encode" => text(encoding::query_escape(texts::<1>(args)?[0])),
        "url_decode" => {
            let [s] = texts(args)?;
            text(encoding::unescape(s, true).ok_or("invalid URL escape")?)
        }
        "from_yaml" => Err("YAML is not read by this agent".into()),
        _ => unknown(),
    }
}

/// Base64 with its padding, as Go's StdEncoding and URLEncoding take it.
fn decoded(
    [text]: [&str; 1],
    decode: fn(&str) -> Option<Vec<u8>>,
) -> Result<Value, String> {
    let bytes = (text.len() % 4 == 0)
        .then(|| decode(text))
        .flatten()
        .ok_or("not base64")?;
    Ok(Value::String(String::from_utf8_lossy(&bytes).into_owned()))
}

fn from_json(json: &Json) -> Value {
    match json {
        Json::Null => Value::Null,
        Json::Bool(b) => Value::Bool(*b),
        Json::Num(n) => Value::Number(*n),
        Json::Str(s) => Value::String(s.clone()),
        Json::Arr(items) => Value::Array(items.iter().map(from_json).collect()),
        Json::Obj(fields) => Value::Object(
            fields
                .iter()
                .map(|(k, v)| (k.clone(), from_json(v)))
                .collect(),
        ),
    }
}

/// Only an object, as Alloy's to_json takes.
fn to_json(args: &[Value]) -> Result<Json, String> {
    match args {
        [object @ Value::Object(_)] => json_of(object),
        _ => Err("takes one object".into()),
    }
}

fn json_of(value: &Value) -> Result<Json, String> {
    Ok(match value {
        Value::Null => Json::Null,
        Value::Bool(b) => Json::Bool(*b),
        Value::Number(n) => Json::Num(*n),
        Value::String(s) => Json::Str(s.clone()),
        Value::Array(items) => {
            Json::Arr(items.iter().map(json_of).collect::<Result<_, _>>()?)
        }
        Value::Object(fields) => Json::Obj(
            fields
                .iter()
                .map(|(k, v)| Ok((k.clone(), json_of(v)?)))
                .collect::<Result<_, String>>()?,
        ),
        other => return Err(format!("cannot encode a {}", other.kind())),
    })
}

fn array(name: &str, args: Vec<Value>) -> Result<Value, String> {
    match name {
        "concat" => concat(args),
        "combine_maps" => combine_maps(args),
        "group_by" => group_by(&args),
        _ => unknown(),
    }
}

fn dynamic(args: &[Value]) -> bool {
    args.iter()
        .any(|v| matches!(v, Value::Capsule(Capsule::Targets(_))))
}

/// Arrays joined; targets that may change join into such targets.
fn concat(args: Vec<Value>) -> Result<Value, String> {
    if dynamic(&args) {
        let parts: Result<Vec<Targets>, String> =
            args.into_iter().map(targets_of).collect();
        return Ok(Value::Capsule(Capsule::Targets(Targets::Concat(parts?))));
    }
    let mut out = Vec::new();
    for arg in args {
        match arg {
            Value::Array(items) => out.extend(items),
            other => {
                return Err(format!("takes arrays, not a {}", other.kind()));
            }
        }
    }
    Ok(Value::Array(out))
}

/// Left maps, right maps, the keys to join on, maybe whether to keep
/// left maps that do not join. Targets that may change make such
/// targets, joined each time they are used.
fn combine_maps(mut args: Vec<Value>) -> Result<Value, String> {
    let keep = match args.get(3) {
        None => false,
        Some(Value::Bool(keep)) => *keep,
        Some(_) => return Err("takes a bool fourth".into()),
    };
    if !(3..=4).contains(&args.len()) {
        return Err("takes 3 or 4 arguments".into());
    }
    let on = match &args[2] {
        Value::Array(keys) if keys.is_empty() => {
            return Err("merge conditions must not be empty".into());
        }
        Value::Array(keys) => keys.iter().map(key).collect::<Result<_, _>>()?,
        _ => return Err("takes an array of keys third".into()),
    };
    args.truncate(2);
    if dynamic(&args) {
        let sides: Vec<Targets> =
            args.into_iter().map(targets_of).collect::<Result<_, _>>()?;
        let sides: [Targets; 2] = sides.try_into().ok().ok_or("two sides")?;
        let combined = Targets::Combine(Box::new(sides), on, keep);
        return Ok(Value::Capsule(Capsule::Targets(combined)));
    }
    let [left, right] = [&args[0], &args[1]].map(objects);
    let joined = combine(&left?, &right?, &on, keep, equal);
    Ok(Value::Array(
        joined.into_iter().map(Value::Object).collect(),
    ))
}

fn key(value: &Value) -> Result<String, String> {
    match value {
        Value::String(key) => Ok(key.clone()),
        other => Err(format!("a key is a string, not a {}", other.kind())),
    }
}

type Map = Vec<(String, Value)>;

fn objects(value: &Value) -> Result<Vec<Map>, String> {
    let Value::Array(items) = value else {
        return Err(format!("takes arrays, not a {}", value.kind()));
    };
    items
        .iter()
        .map(|item| match item {
            Value::Object(fields) => Ok(fields.clone()),
            other => Err(format!("takes objects, not a {}", other.kind())),
        })
        .collect()
}

/// Objects grouped by their string under `key`, as `{<key>, items}`;
/// those without it go to the "" group, or are dropped. Alloy leaves
/// the groups in a map's random order: here they are sorted.
fn group_by(args: &[Value]) -> Result<Value, String> {
    let [array, Value::String(key), Value::Bool(drop)] = args else {
        return Err("takes an array, a string and a bool".into());
    };
    let mut groups: Vec<(String, Vec<Value>)> = Vec::new();
    for item in objects(array)? {
        let name = match item.iter().find(|(k, _)| k == key) {
            Some((_, Value::String(name))) => name.clone(),
            Some((_, other)) => {
                return Err(format!("`{key}` is a {}", other.kind()));
            }
            None if *drop => continue,
            None => String::new(),
        };
        let item = Value::Object(item);
        match groups.iter_mut().find(|(n, _)| *n == name) {
            Some((_, items)) => items.push(item),
            None => groups.push((name, vec![item])),
        }
    }
    groups.sort_by(|a, b| a.0.cmp(&b.0));
    let grouped = groups.into_iter().map(|(name, items)| {
        let mut fields = vec![("items".to_owned(), Value::Array(items))];
        if key != "items" {
            fields.insert(0, (key.clone(), Value::String(name)));
        }
        Value::Object(fields)
    });
    Ok(Value::Array(grouped.collect()))
}

/// The first argument that is not Go's zero value nor empty, else the
/// last one.
// shortcut: targets that may change count as not empty, as they are
// only known when used; resolve them here if a config needs that.
fn coalesce(args: Vec<Value>) -> Value {
    let empty = |value: &Value| match value {
        Value::Null => true,
        Value::Bool(b) => !b,
        Value::Number(n) => *n == 0.0,
        Value::String(s) => s.is_empty(),
        Value::Array(a) => a.is_empty(),
        Value::Object(o) => o.is_empty(),
        Value::Capsule(_) => false,
    };
    let last = args.last().cloned().unwrap_or(Value::Null);
    args.into_iter().find(|v| !empty(v)).unwrap_or(last)
}

/// Go's filepath.Join: the non-empty parts joined by `/`, cleaned.
fn path_join(args: &[Value]) -> Result<Value, String> {
    let parts: Vec<&str> = args
        .iter()
        .map(|arg| match arg {
            Value::String(part) => Ok(part.as_str()),
            other => Err(format!("takes strings, not a {}", other.kind())),
        })
        .filter(|part| part.as_ref().is_ok_and(|p| !p.is_empty()))
        .collect::<Result<_, _>>()?;
    match parts.is_empty() {
        true => Ok(Value::String(String::new())),
        false => Ok(Value::String(clean(&parts.join("/")))),
    }
}

/// Go's path.Clean.
fn clean(path: &str) -> String {
    let rooted = path.starts_with('/');
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." if parts.last().is_some_and(|p| *p != "..") => {
                parts.pop();
            }
            ".." if rooted => {}
            part => parts.push(part),
        }
    }
    let body = parts.join("/");
    match (rooted, body.is_empty()) {
        (true, _) => format!("/{body}"),
        (false, true) => ".".into(),
        (false, false) => body,
    }
}

enum Step {
    Child(String),
    Index(i64),
    Wildcard,
    /// `..`: the node and everything under it.
    Descend,
}

/// What `path` finds in the JSON `text`, always an array. Paths take
/// `$`, `.name`, `..`, `*`, `[n]`, `['name']`; filters, slices and
/// unions are refused.
fn json_path(text: &str, path: &str) -> Result<Value, String> {
    let json = Json::parse(text).ok_or("not JSON")?;
    let mut found = vec![&json];
    for step in steps(path)? {
        found = found
            .into_iter()
            .flat_map(|json| apply(&step, json))
            .collect();
    }
    Ok(Value::Array(found.into_iter().map(from_json).collect()))
}

fn apply<'a>(step: &Step, json: &'a Json) -> Vec<&'a Json> {
    match (step, json) {
        (Step::Child(name), Json::Obj(_)) => {
            json.get(name).into_iter().collect()
        }
        (Step::Index(at), Json::Arr(items)) => {
            let at = if *at < 0 {
                items.len() as i64 + at
            } else {
                *at
            };
            usize::try_from(at)
                .ok()
                .and_then(|at| items.get(at))
                .into_iter()
                .collect()
        }
        (Step::Wildcard, Json::Arr(items)) => items.iter().collect(),
        (Step::Wildcard, Json::Obj(fields)) => {
            let mut sorted: Vec<_> = fields.iter().collect();
            sorted.sort_by(|a, b| a.0.cmp(&b.0));
            sorted.into_iter().map(|(_, v)| v).collect()
        }
        (Step::Descend, _) => {
            let mut all = vec![json];
            for child in apply(&Step::Wildcard, json) {
                all.extend(apply(&Step::Descend, child));
            }
            all
        }
        _ => Vec::new(),
    }
}

fn steps(path: &str) -> Result<Vec<Step>, String> {
    let refused = || format!("`{path}`: only $ . .. * [n] ['name'] here");
    let mut rest = path.strip_prefix('$').unwrap_or(path);
    let mut steps = Vec::new();
    if !rest.is_empty() && !rest.starts_with(['.', '[']) {
        rest = name_step(rest, &mut steps);
    }
    while !rest.is_empty() {
        if let Some(after) = rest.strip_prefix("..") {
            steps.push(Step::Descend);
            rest = match after.starts_with('[') {
                true => after,
                false => name_step(after, &mut steps),
            };
        } else if let Some(after) = rest.strip_prefix('.') {
            rest = name_step(after, &mut steps);
        } else if let Some(after) = rest.strip_prefix('[') {
            let (inside, after) = after.split_once(']').ok_or_else(refused)?;
            steps.push(bracket(inside.trim()).ok_or_else(refused)?);
            rest = after;
        } else {
            return Err(refused());
        }
    }
    Ok(steps)
}

/// A name or `*` up to the next `.` or `[`; the rest of the path.
fn name_step<'a>(text: &'a str, steps: &mut Vec<Step>) -> &'a str {
    let end = text.find(['.', '[']).unwrap_or(text.len());
    match &text[..end] {
        "*" => steps.push(Step::Wildcard),
        name => steps.push(Step::Child(name.to_owned())),
    }
    &text[end..]
}

fn bracket(inside: &str) -> Option<Step> {
    if inside == "*" {
        return Some(Step::Wildcard);
    }
    if let Ok(at) = inside.parse() {
        return Some(Step::Index(at));
    }
    let quoted = ['\'', '"']
        .iter()
        .find_map(|&q| inside.strip_prefix(q)?.strip_suffix(q))?;
    (!quoted.contains(['\'', '"'])).then(|| Step::Child(quoted.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(text: &str) -> Value {
        Value::String(text.into())
    }

    fn text(value: Value) -> String {
        match value {
            Value::String(s) => s,
            other => panic!("a {}", other.kind()),
        }
    }

    fn json(value: Value) -> String {
        match value {
            Value::Array(items) => json_of(&Value::Array(items)),
            object => json_of(&object),
        }
        .unwrap()
        .go_text()
    }

    #[test]
    fn calls_strings_and_encodings() {
        let cases: [(&str, &[&str], &str); 9] = [
            ("trim", &["xxaxx", "x"], "a"),
            ("string.trim_suffix", &["a.go", ".go"], "a"),
            ("string.replace", &["aXbX", "X", "-"], "a-b-"),
            ("encoding.to_URLbase64", &["\u{fb}"], "w7s="),
            ("encoding.from_base64", &["YQ=="], "a"),
            ("encoding.url_encode", &["a b/"], "a+b%2F"),
            ("encoding.url_decode", &["a+b%2F"], "a b/"),
            ("file.path_join", &["/a/", "", "../b/./c"], "/b/c"),
            ("file.path_join", &["a", "../.."], ".."),
        ];
        for (name, args, want) in cases {
            let args = args.iter().map(|a| s(a)).collect();
            assert_eq!(text(call(name, args).unwrap()), want, "{name}");
        }
        assert!(call("encoding.from_base64", vec![s("YQ")]).is_err());
        let number = Value::Number(9.0);
        let formatted = call("format", vec![s("%s:%d"), s("h"), number]);
        assert_eq!(text(formatted.unwrap()), "h:9");
        let parts = call("split", vec![s("a,b"), s(",")]).unwrap();
        assert_eq!(json(parts), r#"["a","b"]"#);
        let object = s(r#"{"b":[1,2],"a":"<"}"#);
        let object = call("encoding.from_json", vec![object]).unwrap();
        let encoded = call("encoding.to_json", vec![object]).unwrap();
        assert_eq!(text(encoded), r#"{"a":"\u003c","b":[1,2]}"#);
        let last = call("coalesce", vec![s(""), Value::Bool(false)]);
        assert!(matches!(last, Ok(Value::Bool(false))));
    }

    #[test]
    fn finds_json_paths() {
        let doc = r#"{"a":{"b":[{"c":1},{"c":2}]},"d":{"c":3}}"#;
        let found = |path: &str| json(json_path(doc, path).unwrap());
        assert_eq!(found("$.a.b[1].c"), "[2]");
        assert_eq!(found(".a.b[-1]"), r#"[{"c":2}]"#);
        assert_eq!(found("$..c"), "[1,2,3]");
        assert_eq!(found("$['d'].*"), "[3]");
        assert_eq!(found("$.x"), "[]");
        assert!(json_path(doc, "$.a[?(@.b)]").is_err());
    }

    #[test]
    fn combines_and_groups_maps() {
        let map = |pairs: &[(&str, &str)]| {
            Value::Object(
                pairs.iter().map(|(k, v)| (k.to_string(), s(v))).collect(),
            )
        };
        let left = Value::Array(vec![
            map(&[("ip", "1"), ("a", "x")]),
            map(&[("ip", "2")]),
        ]);
        let right = Value::Array(vec![map(&[("ip", "1"), ("a", "y")])]);
        let on = Value::Array(vec![s("ip")]);
        let args =
            vec![left.clone(), right.clone(), on.clone(), Value::Bool(true)];
        assert_eq!(
            json(call("array.combine_maps", args).unwrap()),
            r#"[{"a":"y","ip":"1"},{"ip":"2"}]"#
        );
        assert!(
            call(
                "array.combine_maps",
                vec![left.clone(), right, Value::Array(vec![])]
            )
            .is_err()
        );
        let grouped =
            call("array.group_by", vec![left, s("a"), Value::Bool(false)])
                .unwrap();
        assert_eq!(
            json(grouped),
            concat!(
                r#"[{"a":"","items":[{"ip":"2"}]},"#,
                r#"{"a":"x","items":[{"a":"x","ip":"1"}]}]"#,
            )
        );
    }
}
