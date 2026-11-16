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
    /// Alloy's uint: literals past int64, and uint arithmetic.
    Uint(u64),
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
            Value::Int(_) | Value::Uint(_) | Value::Number(_) => "number",
            Value::String(_) => "string",
            Value::Array(_) => "array",
            Value::Object(_) => "object",
            Value::Capsule(Capsule::Targets(_)) => "targets",
            Value::Capsule(Capsule::Rules(_)) => "rules",
            Value::Capsule(_) => "receiver",
        }
    }

    /// Any kind of number, as a float.
    pub fn number(&self) -> Option<f64> {
        self.num().map(Num::float)
    }

    fn num(&self) -> Option<Num> {
        match self {
            Value::Uint(n) => Some(Num::Uint(*n)),
            Value::Int(n) => Some(Num::Int(*n)),
            Value::Number(n) => Some(Num::Float(*n)),
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
        Kind::Uint(n) => Value::Uint(*n),
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
        (Value::Array(items), Value::Int(n)) => {
            nth(items, usize::try_from(n).ok(), n, pos)
        }
        (Value::Array(items), Value::Uint(n)) => {
            nth(items, usize::try_from(n).ok(), n, pos)
        }
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

fn nth(
    items: Vec<Value>,
    at: Option<usize>,
    index: impl std::fmt::Display,
    pos: Pos,
) -> Result<Value, String> {
    at.and_then(|n| items.into_iter().nth(n))
        .ok_or(format!("{pos}: index {index} out of range"))
}

fn unary(op: &str, value: Value, pos: Pos) -> Result<Value, String> {
    match (op, value) {
        ("!", value) => Ok(Value::Bool(!value.truthy(pos)?)),
        ("-", Value::Int(n)) => Ok(Value::Int(n.wrapping_neg())),
        // As Alloy: a negated uint is an int.
        ("-", Value::Uint(n)) => Ok(Value::Int((n as i64).wrapping_neg())),
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
    let (Some(a), Some(b)) = (left.num(), right.num()) else {
        return Err(wrong());
    };
    if matches!(op, "/" | "%") && b.is_zero() {
        return Err(format!("{pos}: divide by zero error"));
    }
    // Wrapping as Go's ints do.
    let found = match fit(a, b) {
        (Num::Uint(a), Num::Uint(b)) => uint_op(op, a, b),
        (Num::Int(a), Num::Int(b)) => int_op(op, a, b),
        (a, b) => float_op(op, a.float(), b.float()),
    };
    found.ok_or_else(wrong)
}

/// A number of one of Alloy's kinds, in the order a pair widens to.
#[derive(Clone, Copy)]
enum Num {
    Uint(u64),
    Int(i64),
    Float(f64),
}

impl Num {
    fn rank(self) -> u8 {
        match self {
            Num::Uint(_) => 0,
            Num::Int(_) => 1,
            Num::Float(_) => 2,
        }
    }

    fn is_zero(self) -> bool {
        match self {
            Num::Uint(n) => n == 0,
            Num::Int(n) => n == 0,
            Num::Float(n) => n == 0.0,
        }
    }

    // Converted as Go converts: ints by their bits, floats truncated.
    fn uint(self) -> u64 {
        match self {
            Num::Uint(n) => n,
            Num::Int(n) => n as u64,
            Num::Float(n) => n as u64,
        }
    }

    fn int(self) -> i64 {
        match self {
            Num::Uint(n) => n as i64,
            Num::Int(n) => n,
            Num::Float(n) => n as i64,
        }
    }

    fn float(self) -> f64 {
        match self {
            Num::Uint(n) => n as f64,
            Num::Int(n) => n as f64,
            Num::Float(n) => n,
        }
    }
}

/// Both as the wider kind of the two, as Alloy's fitNumberKinds.
fn fit(a: Num, b: Num) -> (Num, Num) {
    match a.rank().max(b.rank()) {
        0 => (Num::Uint(a.uint()), Num::Uint(b.uint())),
        1 => (Num::Int(a.int()), Num::Int(b.int())),
        _ => (Num::Float(a.float()), Num::Float(b.float())),
    }
}

fn uint_op(op: &str, a: u64, b: u64) -> Option<Value> {
    Some(Value::Uint(match op {
        "+" => a.wrapping_add(b),
        "-" => a.wrapping_sub(b),
        "*" => a.wrapping_mul(b),
        "/" => a / b,
        "%" => a % b,
        "^" if b == 0 => 1,
        "^" => a.wrapping_pow(u32::try_from(b).unwrap_or(u32::MAX)),
        op => return Some(Value::Bool(order(op, Some(a.cmp(&b))))),
    }))
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
        (a, b) if a.num().is_some() && b.num().is_some() => {
            match fit(a.num().unwrap(), b.num().unwrap()) {
                (Num::Uint(a), Num::Uint(b)) => a == b,
                (Num::Int(a), Num::Int(b)) => a == b,
                (a, b) => a.float() == b.float(),
            }
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
        let max = "18446744073709551615";
        assert!(matches!(value(max), Ok(Value::Uint(u64::MAX))));
        let half = value(&format!("{max} / {max}"));
        assert!(matches!(half, Ok(Value::Uint(1))));
        let min = value("-9223372036854775808");
        assert!(matches!(min, Ok(Value::Int(i64::MIN))));
        let format = format!(r#"string.format("%d %x", {max}, {max})"#);
        assert_eq!(string(&format), format!("{max} ffffffffffffffff"));
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

    fn holds(text: &str) -> bool {
        match value(text) {
            Ok(Value::Bool(b)) => b,
            other => panic!("{text}: {:?}", other.map(|v| v.kind())),
        }
    }

    fn error(text: &str) -> String {
        let found = value(text).err().unwrap_or_default();
        found
            .split_once(": ")
            .map_or(found.clone(), |(_, e)| e.to_owned())
    }

    /// Alloy's (Go's) arithmetic: kinds widen uint, int, float; ints
    /// wrap; a power of 0 is 1, a negative one leaves an int as it is.
    #[test]
    fn computes_as_alloy_does() {
        let max = "18446744073709551615";
        assert!(
            matches!(value(&format!("{max} + {max}")), Ok(Value::Uint(m))
            if m == u64::MAX - 1)
        );
        assert!(matches!(value(&format!("{max} % 10")), Ok(Value::Int(-1))));
        let zero = format!("{max} ^ ({max} - {max})");
        assert!(matches!(value(&zero), Ok(Value::Uint(1))));
        let odd = format!("{max} ^ {max}");
        assert!(matches!(value(&odd), Ok(Value::Uint(u64::MAX))));
        let wide = format!("{max} - {max} * 1");
        assert!(matches!(value(&wide), Ok(Value::Int(0))));
        assert!(matches!(value(&format!("-{max}")), Ok(Value::Int(1))));
        assert!(matches!(value("2 ^ 0"), Ok(Value::Int(1))));
        assert!(matches!(value("2 ^ -3"), Ok(Value::Int(2))));
        assert!(matches!(value("-7 % 3"), Ok(Value::Int(-1))));
        assert!(matches!(value("-1.5"), Ok(Value::Number(n)) if n == -1.5));
        assert!(matches!(value("7.5 % 2"), Ok(Value::Number(n)) if n == 1.5));
        assert!(matches!(value("4.0 ^ 0.5"), Ok(Value::Number(n)) if n == 2.0));
        assert_eq!(error("1.5 / 0"), "divide by zero error");
        assert_eq!(error(r#""a" * 2"#), "`*` on a string and a number");
        assert_eq!(error("true + null"), "`+` on a bool and a null");
        assert_eq!(error(r#"-"a""#), "`-` on a string");
    }

    #[test]
    fn compares_and_indexes_as_alloy_does() {
        assert!(holds(r#""a" < "b" && "b" >= "b" && 1 < 2.5"#));
        assert!(holds("null == null && true != false && 3 > 2"));
        assert!(holds("[1, {a = 1}] == [1.0, {a = 1}]"));
        assert!(holds("{a = 1, b = 2} == {b = 2, a = 1}"));
        assert!(!holds("{a = 1} == {a = 1, b = 2}"));
        assert!(!holds(r#""1" == 1 || [1] == [1, 2]"#));
        // The right side is not evaluated: its name need not resolve.
        assert!(!holds("false && nope.x"));
        assert!(holds("true || nope.x"));
        assert_eq!(error("1 && true"), "expected bool, got number");
        assert_eq!(error("!\"a\""), "expected bool, got string");

        assert!(matches!(value("[1, 2, 3][1]"), Ok(Value::Int(2))));
        assert!(matches!(value(r#"{k = "v"}["k"]"#), Ok(Value::String(v))
            if v == "v"));
        assert!(matches!(value("[{a = 1}][0].a"), Ok(Value::Int(1))));
        assert!(matches!(value("{a = 1}.b"), Ok(Value::Null)));
        assert_eq!(error("[1][3]"), "index 3 out of range");
        assert_eq!(error("[1][-1]"), "index -1 out of range");
        assert_eq!(error(r#"[1]["a"]"#), "cannot index a array with a string");
        assert_eq!(error(r#""s".x"#), "`.x` of a string");
        assert_eq!(error("a.b.c.d"), "`.d` of a number");
    }

    #[test]
    fn names_the_platform_as_go_does() {
        let os = value("constants.os");
        assert!(matches!(os, Ok(Value::String(s)) if s == "linux"));
        #[cfg(target_arch = "x86_64")]
        assert_eq!(string("constants.arch"), "amd64");
        assert_eq!(string("constants.hostname"), crate::host::hostname());
    }
}
