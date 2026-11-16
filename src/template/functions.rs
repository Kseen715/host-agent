//! The functions templates may call: Go's builtins, the string
//! functions Promtail adds, and those of sprig's that work on strings
//! and numbers. Go checks types as it calls: a string function given a
//! number fails, as here.

use crate::digest::{hex, sha3_256, sha256};
use crate::encoding::{base64, from_base64, query_escape};
use regex_lite::{NoExpand, Regex};

/// A template value.
#[derive(Clone, Debug, PartialEq)]
pub enum Val {
    Str(String),
    Int(i64),
    /// Only from Alloy's string.format: a uint past int64.
    Uint(u64),
    Float(f64),
    Bool(bool),
    /// A field the entry lacks.
    Nil,
}

const BUILTINS: [&str; 15] = [
    "and", "or", "not", "eq", "ne", "lt", "le", "gt", "ge", "len", "print",
    "printf", "println", "html", "urlquery",
];

const PROMTAIL: [&str; 13] = [
    "ToLower",
    "ToUpper",
    "Replace",
    "Trim",
    "TrimLeft",
    "TrimRight",
    "TrimPrefix",
    "TrimSuffix",
    "TrimSpace",
    "Hash",
    "Sha2Hash",
    "regexReplaceAll",
    "regexReplaceAllLiteral",
];

const SPRIG: [&str; 47] = [
    "lower",
    "upper",
    "title",
    "untitle",
    "trim",
    "trimAll",
    "trimPrefix",
    "trimSuffix",
    "contains",
    "hasPrefix",
    "hasSuffix",
    "replace",
    "repeat",
    "substr",
    "trunc",
    "nospace",
    "quote",
    "squote",
    "cat",
    "indent",
    "nindent",
    "abbrev",
    "b64enc",
    "b64dec",
    "sha256sum",
    "toString",
    "default",
    "empty",
    "coalesce",
    "ternary",
    "regexMatch",
    "regexFind",
    "regexQuoteMeta",
    "atoi",
    "int",
    "int64",
    "float64",
    "add",
    "add1",
    "sub",
    "mul",
    "div",
    "mod",
    "max",
    "min",
    "biggest",
    "len",
];

pub fn known(name: &str) -> bool {
    [&BUILTINS[..], &PROMTAIL, &SPRIG]
        .iter()
        .any(|n| n.contains(&name))
}

impl Val {
    /// As fmt's `%v` prints it.
    pub fn text(&self) -> String {
        match self {
            Val::Str(text) => text.clone(),
            Val::Int(int) => int.to_string(),
            Val::Uint(uint) => uint.to_string(),
            Val::Float(float) => go_float(*float),
            Val::Bool(bool) => bool.to_string(),
            Val::Nil => "<no value>".into(),
        }
    }

    /// Whether `if` takes it as true: not empty, not zero.
    pub fn truth(&self) -> bool {
        match self {
            Val::Str(text) => !text.is_empty(),
            Val::Int(int) => *int != 0,
            Val::Uint(uint) => *uint != 0,
            Val::Float(float) => *float != 0.0,
            Val::Bool(bool) => *bool,
            Val::Nil => false,
        }
    }

    fn kind(&self) -> &'static str {
        match self {
            Val::Str(_) => "string",
            Val::Int(_) => "int",
            Val::Uint(_) => "uint64",
            Val::Float(_) => "float64",
            Val::Bool(_) => "bool",
            Val::Nil => "nil",
        }
    }
}

/// strconv's shortest `%g`: exponents below -4 or from 6 up as `e±XX`.
fn go_float(value: f64) -> String {
    if value.is_nan() {
        return "NaN".into();
    }
    if value.is_infinite() {
        return if value > 0.0 { "+Inf" } else { "-Inf" }.into();
    }
    let scientific = format!("{value:e}");
    let (mantissa, exponent) = scientific.split_once('e').unwrap_or(("0", "0"));
    let exponent: i32 = exponent.parse().unwrap_or(0);
    if (-4..6).contains(&exponent) {
        return value.to_string();
    }
    let sign = if exponent < 0 { '-' } else { '+' };
    format!("{mantissa}e{sign}{:02}", exponent.abs())
}

fn string(value: &Val) -> Result<&str, String> {
    match value {
        Val::Str(text) => Ok(text),
        other => Err(format!("expected string; found {}", other.kind())),
    }
}

fn int(value: &Val) -> Result<i64, String> {
    match value {
        Val::Int(int) => Ok(*int),
        other => Err(format!("expected int; found {}", other.kind())),
    }
}

/// sprig's cast to int64: strings parsed, floats cut, else 0.
fn to_int(value: &Val) -> i64 {
    match value {
        Val::Int(int) => *int,
        Val::Uint(uint) => *uint as i64,
        Val::Float(float) => *float as i64,
        Val::Bool(bool) => i64::from(*bool),
        Val::Str(text) => text.trim().parse().unwrap_or(0),
        Val::Nil => 0,
    }
}

fn to_float(value: &Val) -> f64 {
    match value {
        Val::Float(float) => *float,
        Val::Str(text) => text.trim().parse().unwrap_or(0.0),
        other => to_int(other) as f64,
    }
}

fn regex(pattern: &str) -> Result<Regex, String> {
    Regex::new(pattern).map_err(|e| format!("regexp: {e}"))
}

/// Calls `name`. A table: longer than 40 lines, read whole.
pub fn call(name: &str, args: Vec<Val>) -> Result<Val, String> {
    let wrong =
        || format!("wrong number of args for {name}: got {}", args.len());
    let s = |at: usize| {
        args.get(at)
            .ok_or_else(wrong)
            .and_then(|v| string(v).map_err(|e| format!("{name}: {e}")))
    };
    let i = |at: usize| {
        args.get(at)
            .ok_or_else(wrong)
            .and_then(|v| int(v).map_err(|e| format!("{name}: {e}")))
    };
    let text = |value: String| Ok(Val::Str(value));
    let n = args.len();
    match (name, n) {
        ("not", 1) => Ok(Val::Bool(!args[0].truth())),
        ("eq" | "ne" | "lt" | "le" | "gt" | "ge", _) => compare(name, &args),
        ("len", 1) => match &args[0] {
            Val::Str(s) => Ok(Val::Int(s.len() as i64)),
            other => Err(format!("len of {}", other.kind())),
        },
        ("print", _) => text(sprint(&args)),
        ("println", _) => {
            let words: Vec<String> = args.iter().map(Val::text).collect();
            text(words.join(" ") + "\n")
        }
        ("printf", 1..) => text(printf(s(0)?, &args[1..])),
        ("html", _) => text(html(&sprint(&args))),
        ("urlquery", _) => text(query_escape(&sprint(&args))),
        ("ToLower" | "lower", 1) => text(s(0)?.to_lowercase()),
        ("ToUpper" | "upper", 1) => text(s(0)?.to_uppercase()),
        ("TrimSpace" | "trim", 1) => text(s(0)?.trim().to_owned()),
        ("Trim", 2) => text(cut(s(0)?, s(1)?, true, true)),
        ("TrimLeft", 2) => text(cut(s(0)?, s(1)?, true, false)),
        ("TrimRight", 2) => text(cut(s(0)?, s(1)?, false, true)),
        ("trimAll", 2) => text(cut(s(1)?, s(0)?, true, true)),
        ("TrimPrefix", 2) => {
            text(s(0)?.strip_prefix(s(1)?).unwrap_or(s(0)?).to_owned())
        }
        ("TrimSuffix", 2) => {
            text(s(0)?.strip_suffix(s(1)?).unwrap_or(s(0)?).to_owned())
        }
        ("trimPrefix", 2) => {
            text(s(1)?.strip_prefix(s(0)?).unwrap_or(s(1)?).to_owned())
        }
        ("trimSuffix", 2) => {
            text(s(1)?.strip_suffix(s(0)?).unwrap_or(s(1)?).to_owned())
        }
        ("Replace", 4) => text(replace(s(0)?, s(1)?, s(2)?, i(3)?)),
        ("replace", 3) => text(s(2)?.replace(s(0)?, s(1)?)),
        ("Hash", 2) => {
            text(hex(&sha3_256(format!("{}{}", s(0)?, s(1)?).as_bytes())))
        }
        ("Sha2Hash", 2) => {
            text(hex(&sha256(format!("{}{}", s(0)?, s(1)?).as_bytes())))
        }
        ("sha256sum", 1) => text(hex(&sha256(s(0)?.as_bytes()))),
        ("regexReplaceAll", 3) => {
            text(regex(s(0)?)?.replace_all(s(1)?, s(2)?).into_owned())
        }
        ("regexReplaceAllLiteral", 3) => text(
            regex(s(0)?)?
                .replace_all(s(1)?, NoExpand(s(2)?))
                .into_owned(),
        ),
        ("regexMatch", 2) => Ok(Val::Bool(regex(s(0)?)?.is_match(s(1)?))),
        ("regexFind", 2) => {
            let found =
                regex(s(0)?)?.find(s(1)?).map(|m| m.as_str().to_owned());
            text(found.unwrap_or_default())
        }
        ("regexQuoteMeta", 1) => text(regex_lite::escape(s(0)?)),
        ("contains", 2) => Ok(Val::Bool(s(1)?.contains(s(0)?))),
        ("hasPrefix", 2) => Ok(Val::Bool(s(1)?.starts_with(s(0)?))),
        ("hasSuffix", 2) => Ok(Val::Bool(s(1)?.ends_with(s(0)?))),
        ("title", 1) => text(title(s(0)?, true)),
        ("untitle", 1) => text(title(s(0)?, false)),
        ("repeat", 2) => {
            text(s(1)?.repeat(usize::try_from(i(0)?).unwrap_or(0)))
        }
        ("substr", 3) => text(substr(i(0)?, i(1)?, s(2)?)),
        ("trunc", 2) => text(trunc(i(0)?, s(1)?)),
        ("nospace", 1) => text(s(0)?.split_whitespace().collect()),
        ("indent", 2) => text(indent(i(0)?, s(1)?)),
        ("nindent", 2) => text(format!("\n{}", indent(i(0)?, s(1)?))),
        ("abbrev", 2) => text(abbrev(i(0)?, s(1)?)),
        ("b64enc", 1) => text(base64(s(0)?.as_bytes())),
        ("b64dec", 1) => text(match from_base64(s(0)?) {
            Some(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
            None => "illegal base64 data".into(),
        }),
        ("quote" | "squote", _) => text(quote(name == "quote", &args)),
        ("cat", _) => {
            let words: Vec<String> = args
                .iter()
                .filter(|v| **v != Val::Nil)
                .map(Val::text)
                .collect();
            text(words.join(" "))
        }
        ("toString", 1) => text(args[0].text()),
        ("default", 1..=2) => Ok(match args.get(1) {
            Some(given) if given.truth() => given.clone(),
            _ => args[0].clone(),
        }),
        ("empty", 1) => Ok(Val::Bool(!args[0].truth())),
        ("coalesce", _) => {
            Ok(args.iter().find(|v| v.truth()).cloned().unwrap_or(Val::Nil))
        }
        ("ternary", 3) => match &args[2] {
            Val::Bool(true) => Ok(args[0].clone()),
            Val::Bool(false) => Ok(args[1].clone()),
            other => {
                Err(format!("ternary: expected bool; found {}", other.kind()))
            }
        },
        ("atoi", 1) => Ok(Val::Int(s(0)?.parse().unwrap_or(0))),
        ("int" | "int64", 1) => Ok(Val::Int(to_int(&args[0]))),
        ("float64", 1) => Ok(Val::Float(to_float(&args[0]))),
        ("add1", 1) => Ok(Val::Int(to_int(&args[0]) + 1)),
        ("add" | "mul" | "max" | "min" | "biggest", 1..) => {
            Ok(Val::Int(fold(name, &args)))
        }
        ("sub", 2) => {
            Ok(Val::Int(to_int(&args[0]).wrapping_sub(to_int(&args[1]))))
        }
        ("div" | "mod", 2) => {
            let (a, b) = (to_int(&args[0]), to_int(&args[1]));
            if b == 0 {
                return Err(format!("{name}: integer divide by zero"));
            }
            Ok(Val::Int(if name == "div" { a / b } else { a % b }))
        }
        _ => Err(wrong()),
    }
}

fn fold(name: &str, args: &[Val]) -> i64 {
    let ints = args.iter().map(to_int);
    match name {
        "add" => ints.fold(0, i64::wrapping_add),
        "mul" => ints.fold(1, i64::wrapping_mul),
        "min" => ints.min().unwrap_or(0),
        _ => ints.max().unwrap_or(0),
    }
}

/// Go's eq (any of the rest equal to the first) and orderings: values
/// of one basic kind only.
fn compare(name: &str, args: &[Val]) -> Result<Val, String> {
    let (first, rest) = args
        .split_first()
        .ok_or("missing argument for comparison")?;
    if rest.is_empty() || (name != "eq" && rest.len() > 1) {
        return Err(format!("wrong number of args for {name}"));
    }
    let order = |b: &Val| -> Result<std::cmp::Ordering, String> {
        let ordering = match (first, b) {
            (Val::Str(a), Val::Str(b)) => a.partial_cmp(b),
            (Val::Int(a), Val::Int(b)) => a.partial_cmp(b),
            (Val::Float(a), Val::Float(b)) => a.partial_cmp(b),
            (Val::Int(a), Val::Float(b)) => (*a as f64).partial_cmp(b),
            (Val::Float(a), Val::Int(b)) => a.partial_cmp(&(*b as f64)),
            (Val::Bool(a), Val::Bool(b)) if matches!(name, "eq" | "ne") => {
                a.partial_cmp(b)
            }
            _ => None,
        };
        ordering.ok_or_else(|| "incompatible types for comparison".to_owned())
    };
    use std::cmp::Ordering::*;
    let result = match name {
        "eq" => rest
            .iter()
            .map(order)
            .collect::<Result<Vec<_>, _>>()?
            .contains(&Equal),
        "ne" => order(&rest[0])? != Equal,
        "lt" => order(&rest[0])? == Less,
        "le" => order(&rest[0])? != Greater,
        "gt" => order(&rest[0])? == Greater,
        _ => order(&rest[0])? != Less,
    };
    Ok(Val::Bool(result))
}

/// fmt.Sprint: spaces between operands when neither is a string.
fn sprint(args: &[Val]) -> String {
    let mut out = String::new();
    for (at, value) in args.iter().enumerate() {
        let string = |v: &Val| matches!(v, Val::Str(_));
        if at > 0 && !string(value) && !string(&args[at - 1]) {
            out.push(' ');
        }
        out.push_str(&value.text());
    }
    out
}

/// fmt.Sprintf's verbs s, v, d, q, f, x, X, t and %%, with flags `-`,
/// `0`, `+`, a width and a precision.
pub fn printf(format: &str, args: &[Val]) -> String {
    let mut out = String::new();
    let mut args = args.iter();
    let mut chars = format.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        let mut spec = String::new();
        while let Some(&c) = chars.peek() {
            if c.is_ascii_alphabetic() || c == '%' {
                break;
            }
            spec.push(c);
            chars.next();
        }
        let Some(verb) = chars.next() else {
            out.push_str("%!(NOVERB)");
            break;
        };
        if verb == '%' {
            out.push('%');
            continue;
        }
        match args.next() {
            Some(value) => out.push_str(&verb_text(verb, &spec, value)),
            None => out.push_str(&format!("%!{verb}(MISSING)")),
        }
    }
    let extra: Vec<String> =
        args.map(|v| format!("{}={}", v.kind(), v.text())).collect();
    if !extra.is_empty() {
        out.push_str(&format!("%!(EXTRA {})", extra.join(", ")));
    }
    out
}

fn verb_text(verb: char, spec: &str, value: &Val) -> String {
    let left = spec.contains('-');
    let zero =
        spec.starts_with('0') || spec.contains("+0") || spec.contains("-0");
    let plus = spec.contains('+');
    let digits = spec.trim_start_matches(['-', '+', '0', ' ', '#']);
    let (width, precision) = match digits.split_once('.') {
        Some((w, p)) => (w.parse().ok(), Some(p.parse().unwrap_or(0))),
        None => (digits.parse().ok(), None),
    };
    let body = match (verb, value) {
        ('s' | 'v', Val::Str(s)) => match precision {
            Some(p) => s.chars().take(p).collect(),
            None => s.clone(),
        },
        ('v', other) => other.text(),
        ('d', Val::Int(i)) if plus && *i >= 0 => format!("+{i}"),
        ('d', Val::Int(i)) => i.to_string(),
        ('d', Val::Uint(u)) if plus => format!("+{u}"),
        ('d', Val::Uint(u)) => u.to_string(),
        ('f' | 'F', Val::Float(f)) => format!("{f:.*}", precision.unwrap_or(6)),
        ('f' | 'F', Val::Int(i)) => return format!("%!f(int={i})"),
        ('x', Val::Int(i)) => format!("{i:x}"),
        ('X', Val::Int(i)) => format!("{i:X}"),
        ('x', Val::Uint(u)) => format!("{u:x}"),
        ('X', Val::Uint(u)) => format!("{u:X}"),
        ('x', Val::Str(s)) => hex(s.as_bytes()),
        ('t', Val::Bool(b)) => b.to_string(),
        ('q', Val::Str(s)) => go_quote(s, '"'),
        (verb, other) => {
            return format!("%!{verb}({}={})", other.kind(), other.text());
        }
    };
    pad(body, width.unwrap_or(0), left, zero && !left && verb != 's')
}

fn pad(body: String, width: usize, left: bool, zero: bool) -> String {
    let missing = width.saturating_sub(body.chars().count());
    match (left, zero) {
        (true, _) => body + &" ".repeat(missing),
        (false, true) => {
            let (sign, digits) = match body.strip_prefix(['-', '+']) {
                Some(digits) => (&body[..1], digits),
                None => ("", body.as_str()),
            };
            format!("{sign}{}{digits}", "0".repeat(missing))
        }
        (false, false) => " ".repeat(missing) + &body,
    }
}

/// strconv.Quote, near enough: escapes for quotes, backslashes and
/// control characters.
fn go_quote(text: &str, quote: char) -> String {
    let mut out = String::from(quote);
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if c.is_control() => {
                out.push_str(&format!("\\x{:02x}", c as u32))
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

/// sprig's quote and squote: each value not nil, quoted, joined by
/// spaces.
fn quote(double: bool, args: &[Val]) -> String {
    let quoted =
        args.iter()
            .filter(|v| **v != Val::Nil)
            .map(|v| match double {
                true => go_quote(&v.text(), '"'),
                false => format!("'{}'", v.text()),
            });
    quoted.collect::<Vec<_>>().join(" ")
}

fn html(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&#34;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// strings.Trim and its sides: characters of `cutset` taken off.
fn cut(text: &str, cutset: &str, start: bool, end: bool) -> String {
    let mut text = text;
    if start {
        text = text.trim_start_matches(|c| cutset.contains(c));
    }
    if end {
        text = text.trim_end_matches(|c| cutset.contains(c));
    }
    text.to_owned()
}

/// strings.Replace: `n` < 0 replaces all.
fn replace(text: &str, old: &str, new: &str, n: i64) -> String {
    match usize::try_from(n) {
        Ok(n) => text.replacen(old, new, n),
        Err(_) => text.replace(old, new),
    }
}

/// strings.Title (each word's first letter up) or sprig's untitle.
fn title(text: &str, up: bool) -> String {
    let mut out = String::with_capacity(text.len());
    let mut start = true;
    for c in text.chars() {
        if start && c.is_alphanumeric() {
            match up {
                true => out.extend(c.to_uppercase()),
                false => out.extend(c.to_lowercase()),
            }
        } else {
            out.push(c);
        }
        start = !c.is_alphanumeric() && c != '\'' && c != '_';
    }
    out
}

/// sprig's substr, by bytes: a start below 0 is 0, an end below 0 or
/// past the text is its end.
fn substr(start: i64, end: i64, text: &str) -> String {
    let len = text.len() as i64;
    let start = start.clamp(0, len) as usize;
    let end = if end < 0 || end > len { len } else { end } as usize;
    let bytes = text
        .as_bytes()
        .get(start..end.max(start))
        .unwrap_or_default();
    String::from_utf8_lossy(bytes).into_owned()
}

/// sprig's trunc: the first `count` bytes, or the last `-count`.
fn trunc(count: i64, text: &str) -> String {
    let len = text.len() as i64;
    let bytes = text.as_bytes();
    let kept = match count {
        c if c < 0 && -c < len => &bytes[(len + c) as usize..],
        c if c >= 0 && len > c => &bytes[..c as usize],
        _ => bytes,
    };
    String::from_utf8_lossy(kept).into_owned()
}

fn indent(spaces: i64, text: &str) -> String {
    let pad = " ".repeat(usize::try_from(spaces).unwrap_or(0));
    format!("{pad}{}", text.replace('\n', &format!("\n{pad}")))
}

/// sprig's abbrev: cut to `width` with `...`; under 4, as it is.
fn abbrev(width: i64, text: &str) -> String {
    let width = usize::try_from(width).unwrap_or(0);
    if width < 4 || text.len() <= width {
        return text.to_owned();
    }
    let kept = text.as_bytes().get(..width - 3).unwrap_or_default();
    format!("{}...", String::from_utf8_lossy(kept))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(text: &str) -> Val {
        Val::Str(text.into())
    }

    #[test]
    fn calls_as_go_and_sprig() {
        let call =
            |name: &str, args: Vec<Val>| call(name, args).unwrap().text();
        assert_eq!(call("trimAll", vec![s("$"), s("$5.00$")]), "5.00");
        assert_eq!(
            call("substr", vec![Val::Int(1), Val::Int(3), s("hello")]),
            "el"
        );
        assert_eq!(call("trunc", vec![Val::Int(-3), s("hello")]), "llo");
        assert_eq!(
            call("abbrev", vec![Val::Int(5), s("hello world")]),
            "he..."
        );
        assert_eq!(
            call("title", vec![s("hello wide world")]),
            "Hello Wide World"
        );
        assert_eq!(
            call(
                "regexReplaceAll",
                vec![s("a(x*)b"), s("-ab-axxb-"), s("${1}W")]
            ),
            "-W-xxW-"
        );
        assert_eq!(
            call("print", vec![Val::Int(1), Val::Int(2), s("a")]),
            "1 2a"
        );
        assert_eq!(call("add", vec![Val::Int(1), s("2")]), "3");
        assert_eq!(go_float(1e6), "1e+06");
        assert_eq!(go_float(123456.0), "123456");
        assert_eq!(go_float(0.00001), "1e-05");
        assert!(super::call("ToLower", vec![Val::Int(1)]).is_err());
        assert!(super::call("eq", vec![Val::Nil, s("a")]).is_err());
        assert_eq!(call("Sha2Hash", vec![s("a"), s("bc")]).len(), 64);
    }

    /// Each function against what Go's text/template, Promtail and
    /// sprig give for the same call.
    #[test]
    fn string_functions_match_go_and_sprig() {
        let i = Val::Int;
        let cases: Vec<(&str, Vec<Val>, &str)> = vec![
            ("ToLower", vec![s("ABC")], "abc"),
            ("upper", vec![s("abc")], "ABC"),
            ("TrimSpace", vec![s("  a \n")], "a"),
            ("Trim", vec![s("xxaxx"), s("x")], "a"),
            ("TrimLeft", vec![s("xya"), s("yx")], "a"),
            ("TrimRight", vec![s("axy"), s("xy")], "a"),
            ("TrimPrefix", vec![s("app-web"), s("app-")], "web"),
            ("TrimSuffix", vec![s("a.log"), s(".log")], "a"),
            ("trimPrefix", vec![s("app-"), s("app-web")], "web"),
            ("trimSuffix", vec![s(".log"), s("a.log")], "a"),
            ("Replace", vec![s("aaa"), s("a"), s("b"), i(2)], "bba"),
            ("Replace", vec![s("aaa"), s("a"), s("b"), i(-1)], "bbb"),
            ("replace", vec![s("a"), s("b"), s("aa")], "bb"),
            (
                "Hash",
                vec![s("a"), s("bc")],
                "3a985da74fe225b2045c172d6bd390bd\
                 855f086e3e9d525b46bfe24511431532",
            ),
            (
                "sha256sum",
                vec![s("abc")],
                "ba7816bf8f01cfea414140de5dae2223\
                 b00361a396177a9cb410ff61f20015ad",
            ),
            (
                "regexReplaceAllLiteral",
                vec![s("a(x*)b"), s("-ab-axxb-"), s("${1}W")],
                "-${1}W-${1}W-",
            ),
            ("regexMatch", vec![s("^a"), s("abc")], "true"),
            ("regexFind", vec![s("[0-9]+"), s("ab12cd34")], "12"),
            ("regexQuoteMeta", vec![s("a.b*")], "a\\.b\\*"),
            ("contains", vec![s("b"), s("abc")], "true"),
            ("hasPrefix", vec![s("b"), s("abc")], "false"),
            ("hasSuffix", vec![s("c"), s("abc")], "true"),
            ("untitle", vec![s("Hello World")], "hello world"),
            ("repeat", vec![i(3), s("ab")], "ababab"),
            ("nospace", vec![s(" a b\tc ")], "abc"),
            ("indent", vec![i(2), s("a\nb")], "  a\n  b"),
            ("nindent", vec![i(1), s("a")], "\n a"),
            ("b64enc", vec![s("hello")], "aGVsbG8="),
            ("b64dec", vec![s("aGVsbG8=")], "hello"),
            ("b64dec", vec![s("!!")], "illegal base64 data"),
            (
                "quote",
                vec![s("a\"b\n"), Val::Nil, i(1)],
                r#""a\"b\n" "1""#,
            ),
            ("squote", vec![s("a"), i(2)], "'a' '2'"),
            ("cat", vec![s("a"), Val::Nil, i(1)], "a 1"),
            ("toString", vec![Val::Float(1.5)], "1.5"),
            (
                "html",
                vec![s("<a href='x'>\"&\"")],
                "&lt;a href=&#39;x&#39;&gt;&#34;&amp;&#34;",
            ),
            ("urlquery", vec![s("a b&c")], "a+b%26c"),
            ("println", vec![s("a"), i(1)], "a 1\n"),
            ("len", vec![s("héllo")], "6"),
            ("not", vec![s("")], "true"),
        ];
        for (name, args, wanted) in cases {
            let got = call(name, args.clone());
            assert_eq!(
                got.map(|v| v.text()),
                Ok(wanted.into()),
                "{name}{args:?}"
            );
        }
    }

    #[test]
    fn values_and_numbers_match_sprig() {
        let i = Val::Int;
        let cases: Vec<(&str, Vec<Val>, Val)> = vec![
            ("default", vec![s("d"), s("")], s("d")),
            ("default", vec![s("d"), s("x")], s("x")),
            ("default", vec![s("d")], s("d")),
            ("empty", vec![i(0)], Val::Bool(true)),
            ("coalesce", vec![Val::Nil, s(""), s("x"), s("y")], s("x")),
            ("coalesce", vec![Val::Nil], Val::Nil),
            ("ternary", vec![s("y"), s("n"), Val::Bool(false)], s("n")),
            ("atoi", vec![s("42")], i(42)),
            ("atoi", vec![s("x")], i(0)),
            ("int", vec![Val::Float(7.9)], i(7)),
            ("int64", vec![Val::Bool(true)], i(1)),
            ("int", vec![Val::Uint(5)], i(5)),
            ("float64", vec![s(" 1.5 ")], Val::Float(1.5)),
            ("float64", vec![i(2)], Val::Float(2.0)),
            ("add1", vec![s("1")], i(2)),
            ("mul", vec![i(2), i(3), i(4)], i(24)),
            ("max", vec![i(1), i(5), i(3)], i(5)),
            ("biggest", vec![i(1), i(5)], i(5)),
            ("min", vec![i(4), i(2)], i(2)),
            ("sub", vec![i(5), i(7)], i(-2)),
            ("div", vec![i(7), i(2)], i(3)),
            ("mod", vec![i(7), i(3)], i(1)),
            ("eq", vec![s("b"), s("a"), s("b")], Val::Bool(true)),
            (
                "ne",
                vec![Val::Bool(true), Val::Bool(false)],
                Val::Bool(true),
            ),
            ("lt", vec![i(1), Val::Float(1.5)], Val::Bool(true)),
            ("le", vec![Val::Float(2.0), i(2)], Val::Bool(true)),
            ("gt", vec![s("b"), s("a")], Val::Bool(true)),
            ("ge", vec![i(1), i(2)], Val::Bool(false)),
        ];
        for (name, args, wanted) in cases {
            assert_eq!(call(name, args.clone()), Ok(wanted), "{name}{args:?}");
        }
        let errors = [
            ("div", vec![i(1), i(0)], "integer divide by zero"),
            ("mod", vec![i(1), i(0)], "integer divide by zero"),
            ("ternary", vec![s("y"), s("n"), s("true")], "expected bool"),
            (
                "lt",
                vec![Val::Bool(true), Val::Bool(false)],
                "incompatible",
            ),
            ("lt", vec![i(1), i(2), i(3)], "wrong number of args"),
            ("eq", vec![], "missing argument"),
            ("len", vec![i(1)], "len of int"),
            ("regexMatch", vec![s("("), s("a")], "regexp:"),
            ("upper", vec![], "wrong number of args for upper: got 0"),
            ("nosuch", vec![], "wrong number of args"),
        ];
        for (name, args, wanted) in errors {
            let error = call(name, args.clone()).unwrap_err();
            assert!(error.contains(wanted), "{name}{args:?}: {error}");
        }
    }

    #[test]
    fn formats_as_fmt_sprintf() {
        let i = Val::Int;
        let cases: Vec<(&str, Vec<Val>, &str)> = vec![
            ("%s-%d", vec![s("a"), i(3)], "a-3"),
            (
                "%5d|%-5d|%05d",
                vec![i(42), i(42), i(-42)],
                "   42|42   |-0042",
            ),
            ("%+d %+d", vec![i(3), Val::Uint(4)], "+3 +4"),
            (
                "%.2f %f",
                vec![Val::Float(1.23456), Val::Float(1.0)],
                "1.23 1.000000",
            ),
            ("%x %X %x", vec![i(255), i(255), s("hi")], "ff FF 6869"),
            ("%x %X", vec![Val::Uint(255), Val::Uint(255)], "ff FF"),
            (
                "%t %v %v",
                vec![Val::Bool(true), i(1), Val::Nil],
                "true 1 <no value>",
            ),
            ("%q", vec![s("a\"b")], r#""a\"b""#),
            (
                "%.3s|%6s|%-3s|",
                vec![s("abcdef"), s("ab"), s("a")],
                "abc|    ab|a  |",
            ),
            ("100%%", vec![], "100%"),
            ("%d %d", vec![i(1)], "1 %!d(MISSING)"),
            ("%d", vec![i(1), s("x")], "1%!(EXTRA string=x)"),
            ("%d", vec![s("x")], "%!d(string=x)"),
            ("%f", vec![i(1)], "%!f(int=1)"),
            ("%", vec![], "%!(NOVERB)"),
        ];
        for (format, args, wanted) in cases {
            assert_eq!(printf(format, &args), wanted, "{format}");
        }
        let via_call = call("printf", vec![s("%s=%d"), s("n"), i(1)]);
        assert_eq!(via_call.unwrap().text(), "n=1");
    }
}
