//! Alloy's values and expressions: literals, operators, references to
//! components' exports, and the standard library functions configs
//! here use (`sys.env`, `constants.*`, `string.format`, `string.join`,
//! `coalesce`, `array.concat`).

use super::syntax::{Expr, Kind, Pos};
use crate::relabel::Rule;
use crate::targets::Targets;
use std::rc::Rc;

#[derive(Clone)]
pub enum Value {
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Array(Vec<Value>),
    Object(Vec<(String, Value)>),
    /// A component's export the syntax cannot spell.
    Capsule(Capsule),
}

#[derive(Clone)]
pub enum Capsule {
    /// Targets that may change while running.
    Targets(Targets),
    Rules(Rc<Vec<Rule>>),
    /// A prometheus.* receiver: the metrics graph's node.
    Metrics(usize),
    /// A loki.* receiver: the logs graph's node.
    Logs(usize),
    /// An otelcol.* consumer: the OTLP graph's node.
    Otel(usize),
}

impl Value {
    pub fn kind(&self) -> &'static str {
        match self {
            Value::Null => "null",
            Value::Bool(_) => "bool",
            Value::Number(_) => "number",
            Value::String(_) => "string",
            Value::Array(_) => "array",
            Value::Object(_) => "object",
            Value::Capsule(Capsule::Targets(_)) => "targets",
            Value::Capsule(Capsule::Rules(_)) => "rules",
            Value::Capsule(_) => "receiver",
        }
    }

    fn truthy(&self, pos: Pos) -> Result<bool, String> {
        match self {
            Value::Bool(b) => Ok(*b),
            other => Err(format!("{pos}: expected bool, got {}", other.kind())),
        }
    }
}

/// What a dotted reference names: a component's export, or None.
pub type Resolve<'a> = &'a dyn Fn(&str) -> Option<Value>;

// One arm per kind of expression: longer than 40 lines, as a table is
// read whole.
pub fn eval(expr: &Expr, resolve: Resolve) -> Result<Value, String> {
    let pos = expr.pos;
    Ok(match &expr.kind {
        Kind::Null => Value::Null,
        Kind::Bool(b) => Value::Bool(*b),
        Kind::Number(n) => Value::Number(*n),
        Kind::Str(s) => Value::String(s.clone()),
        Kind::Array(items) => Value::Array(
            items
                .iter()
                .map(|e| eval(e, resolve))
                .collect::<Result<_, _>>()?,
        ),
        Kind::Object(fields) => {
            let mut out = Vec::new();
            for (key, value) in fields {
                out.push((key.clone(), eval(value, resolve)?));
            }
            Value::Object(out)
        }
        Kind::Ident(_) | Kind::Access(..) => reference(expr, resolve)?,
        Kind::Index(inner, index) => {
            let inner = eval(inner, resolve)?;
            let index = eval(index, resolve)?;
            element(inner, index, pos)?
        }
        Kind::Call(callee, args) => {
            let name = path(callee)
                .ok_or(format!("{pos}: only named functions are called"))?;
            let args: Vec<Value> = args
                .iter()
                .map(|a| eval(a, resolve))
                .collect::<Result<_, _>>()?;
            call(&name, args).map_err(|e| format!("{pos}: {name}: {e}"))?
        }
        Kind::Unary(op, operand) => unary(op, eval(operand, resolve)?, pos)?,
        Kind::Binary(op, left, right) => {
            let left = eval(left, resolve)?;
            // `&&` and `||` look at their right side only when needed.
            match *op {
                "&&" if !left.truthy(pos)? => Value::Bool(false),
                "||" if left.truthy(pos)? => Value::Bool(true),
                "&&" | "||" => Value::Bool(eval(right, resolve)?.truthy(pos)?),
                _ => binary(op, left, eval(right, resolve)?, pos)?,
            }
        }
    })
}

/// `a.b.c` as text, if the expression is only names and dots.
pub(super) fn path(expr: &Expr) -> Option<String> {
    match &expr.kind {
        Kind::Ident(name) => Some(name.clone()),
        Kind::Access(inner, field) => Some(format!("{}.{field}", path(inner)?)),
        _ => None,
    }
}

/// The longest leading part that names something, then its fields.
fn reference(expr: &Expr, resolve: Resolve) -> Result<Value, String> {
    let pos = expr.pos;
    let Some(full) = path(expr) else {
        let Kind::Access(inner, field) = &expr.kind else {
            unreachable!("names are paths");
        };
        return field_of(eval(inner, resolve)?, field, pos);
    };
    let parts: Vec<&str> = full.split('.').collect();
    for end in (1..=parts.len()).rev() {
        let head = parts[..end].join(".");
        let Some(mut value) = constant(&head).or_else(|| resolve(&head)) else {
            continue;
        };
        for field in &parts[end..] {
            value = field_of(value, field, pos)?;
        }
        return Ok(value);
    }
    Err(format!("{pos}: `{full}` names nothing"))
}

fn constant(name: &str) -> Option<Value> {
    let text = match name {
        "constants.hostname" => crate::host::hostname(),
        "constants.os" => std::env::consts::OS.to_owned(),
        "constants.arch" => match std::env::consts::ARCH {
            "x86_64" => "amd64".to_owned(),
            "aarch64" => "arm64".to_owned(),
            other => other.to_owned(),
        },
        _ => return None,
    };
    Some(Value::String(text))
}

fn field_of(value: Value, field: &str, pos: Pos) -> Result<Value, String> {
    match value {
        Value::Object(fields) => Ok(fields
            .into_iter()
            .find(|(k, _)| k == field)
            .map_or(Value::Null, |(_, v)| v)),
        other => Err(format!("{pos}: `.{field}` of a {}", other.kind())),
    }
}

fn element(inner: Value, index: Value, pos: Pos) -> Result<Value, String> {
    match (inner, index) {
        (Value::Array(items), Value::Number(n)) => items
            .into_iter()
            .nth(n as usize)
            .ok_or(format!("{pos}: index {n} out of range")),
        (object @ Value::Object(_), Value::String(key)) => {
            field_of(object, &key, pos)
        }
        (inner, index) => Err(format!(
            "{pos}: cannot index a {} with a {}",
            inner.kind(),
            index.kind()
        )),
    }
}

fn unary(op: &str, value: Value, pos: Pos) -> Result<Value, String> {
    match (op, value) {
        ("!", value) => Ok(Value::Bool(!value.truthy(pos)?)),
        ("-", Value::Number(n)) => Ok(Value::Number(-n)),
        (op, value) => Err(format!("{pos}: `{op}` on a {}", value.kind())),
    }
}

// One arm per operator: longer than 40 lines, as a table is read whole.
fn binary(
    op: &str,
    left: Value,
    right: Value,
    pos: Pos,
) -> Result<Value, String> {
    use Value::{Bool, Number, String as Str};
    Ok(match (op, left, right) {
        ("+", Str(a), Str(b)) => Str(a + &b),
        ("+", Number(a), Number(b)) => Number(a + b),
        ("-", Number(a), Number(b)) => Number(a - b),
        ("*", Number(a), Number(b)) => Number(a * b),
        ("/", Number(a), Number(b)) => Number(a / b),
        ("%", Number(a), Number(b)) => Number(a % b),
        ("^", Number(a), Number(b)) => Number(a.powf(b)),
        ("==", a, b) => Bool(equal(&a, &b)),
        ("!=", a, b) => Bool(!equal(&a, &b)),
        (op @ ("<" | "<=" | ">" | ">="), a, b) => {
            let order = match (&a, &b) {
                (Number(a), Number(b)) => a.partial_cmp(b),
                (Str(a), Str(b)) => Some(a.cmp(b)),
                _ => None,
            };
            let order = order.ok_or(format!(
                "{pos}: cannot compare a {} with a {}",
                a.kind(),
                b.kind()
            ))?;
            Bool(match op {
                "<" => order.is_lt(),
                "<=" => order.is_le(),
                ">" => order.is_gt(),
                _ => order.is_ge(),
            })
        }
        (op, a, b) => {
            return Err(format!(
                "{pos}: `{op}` on a {} and a {}",
                a.kind(),
                b.kind()
            ));
        }
    })
}

fn equal(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Null, Value::Null) => true,
        (Value::Bool(a), Value::Bool(b)) => a == b,
        (Value::Number(a), Value::Number(b)) => a == b,
        (Value::String(a), Value::String(b)) => a == b,
        (Value::Array(a), Value::Array(b)) => {
            a.len() == b.len() && a.iter().zip(b).all(|(a, b)| equal(a, b))
        }
        (Value::Object(a), Value::Object(b)) => {
            a.len() == b.len()
                && a.iter().all(|(k, v)| {
                    b.iter().any(|(k2, v2)| k == k2 && equal(v, v2))
                })
        }
        _ => false,
    }
}

fn call(name: &str, args: Vec<Value>) -> Result<Value, String> {
    match name {
        "sys.env" | "env" => match &args[..] {
            [Value::String(key)] => {
                Ok(Value::String(std::env::var(key).unwrap_or_default()))
            }
            _ => Err("takes one string".into()),
        },
        "coalesce" => {
            Ok(args.into_iter().find(|v| !empty(v)).unwrap_or(Value::Null))
        }
        "array.concat" | "concat" => concat(args),
        "string.join" => match &args[..] {
            [Value::Array(items), Value::String(separator)] => {
                let words: Result<Vec<String>, String> =
                    items.iter().map(|v| text(v, false)).collect();
                Ok(Value::String(words?.join(separator)))
            }
            _ => Err("takes an array of strings and a string".into()),
        },
        "string.format" => match args.split_first() {
            Some((Value::String(format), rest)) => {
                Ok(Value::String(sprintf(format, rest)?))
            }
            _ => Err("takes a format string first".into()),
        },
        _ => Err("not a function this agent has".into()),
    }
}

/// Go's zero values, which coalesce skips.
fn empty(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Bool(b) => !b,
        Value::Number(n) => *n == 0.0,
        Value::String(s) => s.is_empty(),
        Value::Array(a) => a.is_empty(),
        Value::Object(o) => o.is_empty(),
        Value::Capsule(_) => false,
    }
}

/// Arrays joined; targets that may change join into such targets.
fn concat(args: Vec<Value>) -> Result<Value, String> {
    let dynamic = args
        .iter()
        .any(|v| matches!(v, Value::Capsule(Capsule::Targets(_))));
    if !dynamic {
        let mut out = Vec::new();
        for arg in args {
            match arg {
                Value::Array(items) => out.extend(items),
                other => {
                    return Err(format!(
                        "takes arrays, not a {}",
                        other.kind()
                    ));
                }
            }
        }
        return Ok(Value::Array(out));
    }
    let parts: Result<Vec<Targets>, String> =
        args.into_iter().map(super::compile::targets_of).collect();
    Ok(Value::Capsule(Capsule::Targets(Targets::Concat(parts?))))
}

fn text(value: &Value, quote: bool) -> Result<String, String> {
    Ok(match value {
        Value::String(s) if quote => format!("{s:?}"),
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => "<nil>".into(),
        other => return Err(format!("cannot format a {}", other.kind())),
    })
}

/// Go's fmt verbs %s %v %d %f %q %%, as string.format takes them.
fn sprintf(format: &str, args: &[Value]) -> Result<String, String> {
    let mut out = String::new();
    let mut args = args.iter();
    let mut chars = format.chars();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        let verb = chars.next().ok_or("a lone % at the end")?;
        if verb == '%' {
            out.push('%');
            continue;
        }
        let arg = args.next().ok_or("fewer arguments than verbs")?;
        out.push_str(&match (verb, arg) {
            ('d', Value::Number(n)) => format!("{}", n.trunc() as i64),
            ('f', Value::Number(n)) => format!("{n:.6}"),
            ('s' | 'v', value) => text(value, false)?,
            ('q', value) => text(value, true)?,
            (verb, value) => {
                return Err(format!("%{verb} of a {}", value.kind()));
            }
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::super::syntax::{Stmt, parse};
    use super::*;

    fn value(text: &str) -> Result<Value, String> {
        let body = parse(&format!("x = {text}")).unwrap();
        let Stmt::Attr { value, .. } = &body[0] else {
            panic!("not an attribute");
        };
        let resolve = |name: &str| {
            (name == "a.b")
                .then(|| Value::Object(vec![("c".into(), Value::Number(7.0))]))
        };
        eval(value, &resolve)
    }

    fn string(text: &str) -> String {
        match value(text) {
            Ok(Value::String(s)) => s,
            _ => panic!("not a string: {text}"),
        }
    }

    #[test]
    fn evaluates_expressions_and_functions() {
        assert!(matches!(value("1 + 2 * 3"), Ok(Value::Number(7.0))));
        assert!(matches!(value("2 ^ 3 ^ 2"), Ok(Value::Number(512.0))));
        assert!(matches!(value("a.b.c - 1"), Ok(Value::Number(6.0))));
        assert!(matches!(value("!(1 < 2) || 3 >= 3"), Ok(Value::Bool(true))));
        assert_eq!(string(r#""a" + "b""#), "ab");
        assert_eq!(string(r#"string.format("%s:%d", "h", 9100)"#), "h:9100");
        assert_eq!(string(r#"string.join(["a", "b"], ",")"#), "a,b");
        assert_eq!(string(r#"coalesce("", sys.env("NO_SUCH_X"), "z")"#), "z");
        let Ok(Value::Array(items)) = value("array.concat([1], [2, 3])") else {
            panic!("not an array");
        };
        assert_eq!(items.len(), 3);
        let error = value("nope.x").err().unwrap();
        assert!(error.contains("names nothing"));
    }
}
