//! Alloy's values and expressions: literals, operators, references to
//! components' exports, `constants.*`; functions are stdlib.rs's.

use super::syntax::{Expr, Kind, Pos};
use crate::relabel::Rule;
use crate::targets::Targets;
use std::rc::Rc;

#[derive(Clone)]
pub enum Value {
    Null,
    Bool(bool),
    /// Alloy's int: from literals without a fraction, and int arithmetic.
    Int(i64),
    /// Alloy's float.
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
            Value::Int(_) | Value::Number(_) => "number",
            Value::String(_) => "string",
            Value::Array(_) => "array",
            Value::Object(_) => "object",
            Value::Capsule(Capsule::Targets(_)) => "targets",
            Value::Capsule(Capsule::Rules(_)) => "rules",
            Value::Capsule(_) => "receiver",
        }
    }

    /// Either kind of number, as a float.
    pub fn number(&self) -> Option<f64> {
        match self {
            Value::Int(n) => Some(*n as f64),
            Value::Number(n) => Some(*n),
            _ => None,
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
        Kind::Int(n) => Value::Int(*n),
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
            super::stdlib::call(&name, args)
                .map_err(|e| format!("{pos}: {name}: {e}"))?
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
        (Value::Array(items), Value::Int(n)) => usize::try_from(n)
            .ok()
            .and_then(|n| items.into_iter().nth(n))
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
        ("-", Value::Int(n)) => Ok(Value::Int(n.wrapping_neg())),
        ("-", Value::Number(n)) => Ok(Value::Number(-n)),
        (op, value) => Err(format!("{pos}: `{op}` on a {}", value.kind())),
    }
}

fn binary(
    op: &str,
    left: Value,
    right: Value,
    pos: Pos,
) -> Result<Value, String> {
    use Value::{Bool, String as Str};
    match (op, &left, &right) {
        ("==", a, b) => return Ok(Bool(equal(a, b))),
        ("!=", a, b) => return Ok(Bool(!equal(a, b))),
        ("+", Str(a), Str(b)) => return Ok(Str(format!("{a}{b}"))),
        (op @ ("<" | "<=" | ">" | ">="), Str(a), Str(b)) => {
            return Ok(Bool(order(op, Some(a.cmp(b)))));
        }
        _ => {}
    }
    let wrong = || {
        let (a, b) = (left.kind(), right.kind());
        format!("{pos}: `{op}` on a {a} and a {b}")
    };
    let (Some(a), Some(b)) = (left.number(), right.number()) else {
        return Err(wrong());
    };
    if matches!(op, "/" | "%") && b == 0.0 {
        return Err(format!("{pos}: divide by zero error"));
    }
    let found = match (&left, &right) {
        // Alloy keeps two ints an int, wrapping as Go's do.
        (Value::Int(a), Value::Int(b)) => int_op(op, *a, *b),
        _ => float_op(op, a, b),
    };
    found.ok_or_else(wrong)
}

fn int_op(op: &str, a: i64, b: i64) -> Option<Value> {
    Some(Value::Int(match op {
        "+" => a.wrapping_add(b),
        "-" => a.wrapping_sub(b),
        "*" => a.wrapping_mul(b),
        "/" => a.wrapping_div(b),
        "%" => a.wrapping_rem(b),
        // Alloy's intPow: 1 for 0, `a` itself for a negative power.
        "^" if b <= 0 => i64::from(b == 0) + i64::from(b < 0) * a,
        "^" => a.wrapping_pow(u32::try_from(b).unwrap_or(u32::MAX)),
        op => return Some(Value::Bool(order(op, Some(a.cmp(&b))))),
    }))
}

fn float_op(op: &str, a: f64, b: f64) -> Option<Value> {
    Some(Value::Number(match op {
        "+" => a + b,
        "-" => a - b,
        "*" => a * b,
        "/" => a / b,
        "%" => a % b,
        "^" => a.powf(b),
        "<" | "<=" | ">" | ">=" => {
            return Some(Value::Bool(order(op, a.partial_cmp(&b))));
        }
        _ => return None,
    }))
}

/// A comparison's result; NaN compares false, as in Go.
fn order(op: &str, found: Option<std::cmp::Ordering>) -> bool {
    found.is_some_and(|o| match op {
        "<" => o.is_lt(),
        "<=" => o.is_le(),
        ">" => o.is_gt(),
        _ => o.is_ge(),
    })
}

pub(super) fn equal(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Null, Value::Null) => true,
        (Value::Bool(a), Value::Bool(b)) => a == b,
        (a, b) if a.number().is_some() && b.number().is_some() => {
            a.number() == b.number()
        }
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
        assert!(matches!(value("1 + 2 * 3"), Ok(Value::Int(7))));
        assert!(matches!(value("2 ^ 3 ^ 2"), Ok(Value::Int(512))));
        assert!(matches!(value("7 / 2"), Ok(Value::Int(3))));
        assert!(matches!(value("7 / 2.0"), Ok(Value::Number(3.5))));
        assert!(matches!(value("a.b.c - 1"), Ok(Value::Number(6.0))));
        assert!(value("1 % 0").is_err());
        assert!(matches!(value("1 == 1.0"), Ok(Value::Bool(true))));
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
