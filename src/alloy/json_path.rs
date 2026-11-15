//! JSONPath as Alloy's json_path takes it (ojg's jp): `$`, `.name`,
//! `..`, `*`, `[n]`, `['name']`, unions `[a,b]`, slices
//! `[start:end:step]` and filters `[?(...)]` comparing `@` and `$`
//! paths and literals by `==`, `!=`, `<`, `<=`, `>`, `>=`, `=~`, `in`,
//! joined by `&&`, `||`, `!` and parentheses.

use crate::json::Json;
use regex_lite::Regex;

enum Step {
    Child(String),
    Index(i64),
    Wildcard,
    /// `..`: the node and everything under it.
    Descend,
    Slice(Option<i64>, Option<i64>, i64),
    Union(Vec<Step>),
    Filter(Expr),
}

enum Expr {
    /// A path from `@` (false) or `$` (true).
    Path(bool, Vec<Step>),
    Literal(Json),
    List(Vec<Json>),
    Pattern(Regex),
    Not(Box<Expr>),
    Binary(&'static str, Box<Expr>, Box<Expr>),
}

const OPERATORS: [&str; 10] =
    ["==", "!=", "<=", ">=", "=~", "<", ">", "in", "&&", "||"];

/// What `path` finds in `json`, in document order.
pub fn find<'a>(json: &'a Json, path: &str) -> Result<Vec<&'a Json>, String> {
    let mut parser = Parser { text: path, at: 0 };
    parser.eat("$");
    let steps = parser.path(true)?;
    if parser.at < path.len() {
        let rest = &path[parser.at..];
        return Err(format!("`{path}`: unexpected `{rest}`"));
    }
    Ok(walk(&steps, json, json))
}

fn walk<'a>(steps: &[Step], node: &'a Json, root: &'a Json) -> Vec<&'a Json> {
    let mut found = vec![node];
    for step in steps {
        found = found
            .into_iter()
            .flat_map(|j| apply(step, j, root))
            .collect();
    }
    found
}

fn apply<'a>(step: &Step, json: &'a Json, root: &'a Json) -> Vec<&'a Json> {
    match (step, json) {
        (Step::Child(name), Json::Obj(_)) => {
            json.get(name).into_iter().collect()
        }
        (Step::Index(at), Json::Arr(items)) => index(*at, items.len())
            .map(|i| &items[i])
            .into_iter()
            .collect(),
        (Step::Slice(start, end, step), Json::Arr(items)) => {
            let picked = slice(*start, *end, *step, items.len());
            picked.into_iter().map(|i| &items[i]).collect()
        }
        (Step::Union(steps), _) => {
            steps.iter().flat_map(|s| apply(s, json, root)).collect()
        }
        (Step::Wildcard, _) => children(json),
        (Step::Descend, _) => {
            let mut all = vec![json];
            for child in children(json) {
                all.extend(apply(&Step::Descend, child, root));
            }
            all
        }
        (Step::Filter(expr), _) => children(json)
            .into_iter()
            .filter(|child| truth(&value(expr, child, root)))
            .collect(),
        _ => Vec::new(),
    }
}

fn children(json: &Json) -> Vec<&Json> {
    match json {
        Json::Arr(items) => items.iter().collect(),
        Json::Obj(fields) => fields.iter().map(|(_, v)| v).collect(),
        _ => Vec::new(),
    }
}

/// An index, negative from the end, if in range.
fn index(at: i64, len: usize) -> Option<usize> {
    let at = if at < 0 { at + len as i64 } else { at };
    usize::try_from(at).ok().filter(|at| *at < len)
}

/// The indexes `[start:end:step]` picks, as Python's slices.
fn slice(
    start: Option<i64>,
    end: Option<i64>,
    step: i64,
    len: usize,
) -> Vec<usize> {
    let len = len as i64;
    let clamp = |at: i64, low: i64, high: i64| {
        let at = if at < 0 { at + len } else { at };
        at.clamp(low, high)
    };
    let mut picked = Vec::new();
    if step > 0 {
        let mut at = clamp(start.unwrap_or(0), 0, len);
        let end = clamp(end.unwrap_or(len), 0, len);
        while at < end {
            picked.push(at as usize);
            at += step;
        }
    } else if step < 0 {
        let mut at = clamp(start.unwrap_or(len - 1), -1, len - 1);
        let end = end.map_or(-1, |end| clamp(end, -1, len - 1));
        while at > end {
            picked.push(at as usize);
            at += step;
        }
    }
    picked
}

/// An operand's value: a path's first match, None if it has none.
enum Found<'a> {
    Json(Option<&'a Json>),
    Bool(bool),
}

fn value<'a>(expr: &'a Expr, node: &'a Json, root: &'a Json) -> Found<'a> {
    match expr {
        Expr::Path(from_root, steps) => {
            let start = if *from_root { root } else { node };
            Found::Json(walk(steps, start, root).into_iter().next())
        }
        Expr::Literal(json) => Found::Json(Some(json)),
        // Lists and patterns are only `in`'s and `=~`'s.
        Expr::List(_) | Expr::Pattern(_) => Found::Bool(false),
        Expr::Not(inner) => Found::Bool(!truth(&value(inner, node, root))),
        Expr::Binary(op, left, right) => {
            Found::Bool(binary(op, left, right, node, root))
        }
    }
}

fn truth(found: &Found) -> bool {
    match found {
        Found::Bool(b) => *b,
        Found::Json(json) => {
            !matches!(json, None | Some(Json::Null | Json::Bool(false)))
        }
    }
}

fn binary(
    op: &str,
    left: &Expr,
    right: &Expr,
    node: &Json,
    root: &Json,
) -> bool {
    let truth_of = |e| truth(&value(e, node, root));
    match op {
        "&&" => return truth_of(left) && truth_of(right),
        "||" => return truth_of(left) || truth_of(right),
        _ => {}
    }
    let left = value(left, node, root);
    let Found::Json(Some(a)) = left else {
        return false;
    };
    match (op, right) {
        ("=~", Expr::Pattern(regex)) => {
            a.str().is_some_and(|s| regex.is_match(s))
        }
        ("in", Expr::List(items)) => items.iter().any(|b| same(a, b)),
        _ => match value(right, node, root) {
            Found::Json(Some(b)) => compare(op, a, b),
            _ => false,
        },
    }
}

fn compare(op: &str, a: &Json, b: &Json) -> bool {
    let order = match (a, b) {
        (Json::Num(x), Json::Num(y)) => x.partial_cmp(y),
        (Json::Str(x), Json::Str(y)) => Some(x.cmp(y)),
        _ => None,
    };
    match op {
        "==" => same(a, b),
        "!=" => !same(a, b),
        "<" => order.is_some_and(|o| o.is_lt()),
        "<=" => order.is_some_and(|o| o.is_le()),
        ">" => order.is_some_and(|o| o.is_gt()),
        ">=" => order.is_some_and(|o| o.is_ge()),
        _ => false,
    }
}

fn same(a: &Json, b: &Json) -> bool {
    match (a, b) {
        (Json::Null, Json::Null) => true,
        (Json::Bool(x), Json::Bool(y)) => x == y,
        (Json::Num(x), Json::Num(y)) => x == y,
        (Json::Str(x), Json::Str(y)) => x == y,
        (Json::Arr(x), Json::Arr(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(a, b)| same(a, b))
        }
        (Json::Obj(x), Json::Obj(y)) => {
            x.len() == y.len()
                && x.iter().all(|(k, v)| b.get(k).is_some_and(|w| same(v, w)))
        }
        _ => false,
    }
}

struct Parser<'a> {
    text: &'a str,
    at: usize,
}

impl Parser<'_> {
    fn rest(&self) -> &str {
        &self.text[self.at..]
    }

    fn eat(&mut self, token: &str) -> bool {
        self.space();
        let found = self.rest().starts_with(token);
        if found {
            self.at += token.len();
        }
        found
    }

    fn space(&mut self) {
        let rest = self.rest();
        self.at += rest.len() - rest.trim_start().len();
    }

    fn fail<T>(&self, what: &str) -> Result<T, String> {
        Err(format!("`{}`: {what} at `{}`", self.text, self.rest()))
    }

    /// Steps until the path ends; `top`: a bare name may start it.
    fn path(&mut self, top: bool) -> Result<Vec<Step>, String> {
        let mut steps = Vec::new();
        if top && self.rest().starts_with(name_char) {
            steps.push(self.name()?);
        }
        loop {
            if self.rest().starts_with("..") {
                self.at += 2;
                steps.push(Step::Descend);
                if !self.rest().starts_with('[') {
                    steps.push(self.name()?);
                }
            } else if self.rest().starts_with('.') {
                self.at += 1;
                steps.push(self.name()?);
            } else if self.rest().starts_with('[') {
                self.at += 1;
                steps.push(self.bracket()?);
            } else {
                return Ok(steps);
            }
        }
    }

    fn name(&mut self) -> Result<Step, String> {
        if self.rest().starts_with('*') {
            self.at += 1;
            return Ok(Step::Wildcard);
        }
        let end = self
            .rest()
            .find(|c| !name_char(c))
            .unwrap_or(self.rest().len());
        if end == 0 {
            return self.fail("a name expected");
        }
        let name = self.rest()[..end].to_owned();
        self.at += end;
        Ok(Step::Child(name))
    }

    /// What follows `[`, up to and including `]`.
    fn bracket(&mut self) -> Result<Step, String> {
        let step = if self.eat("*") {
            Step::Wildcard
        } else if self.eat("?") {
            if !self.eat("(") {
                return self.fail("`(` expected");
            }
            let expr = self.or()?;
            if !self.eat(")") {
                return self.fail("`)` expected");
            }
            Step::Filter(expr)
        } else {
            let mut items = vec![self.item()?];
            while self.eat(",") {
                items.push(self.item()?);
            }
            match items.len() {
                1 => items.remove(0),
                _ => Step::Union(items),
            }
        };
        match self.eat("]") {
            true => Ok(step),
            false => self.fail("`]` expected"),
        }
    }

    /// A quoted name, an index or a slice.
    fn item(&mut self) -> Result<Step, String> {
        self.space();
        if self.rest().starts_with(['\'', '"']) {
            return Ok(Step::Child(self.quoted()?));
        }
        let start = self.int();
        if !self.eat(":") {
            return start
                .map(Step::Index)
                .map_or(self.fail("an index expected"), Ok);
        }
        let end = self.int();
        let step = if self.eat(":") { self.int() } else { None };
        match step.unwrap_or(1) {
            0 => self.fail("a slice's step of 0"),
            step => Ok(Step::Slice(start, end, step)),
        }
    }

    fn int(&mut self) -> Option<i64> {
        self.space();
        let rest = self.rest();
        let sign = usize::from(rest.starts_with('-'));
        let digits = rest[sign..].find(|c: char| !c.is_ascii_digit());
        let end = sign + digits.unwrap_or(rest.len() - sign);
        let int = rest[..end].parse().ok()?;
        self.at += end;
        Some(int)
    }

    fn quoted(&mut self) -> Result<String, String> {
        let quote = self.rest().chars().next().unwrap_or('\'');
        let mut text = String::new();
        let mut chars = self.rest()[1..].char_indices();
        while let Some((i, c)) = chars.next() {
            match c {
                '\\' => text.extend(chars.next().map(|(_, c)| c)),
                c if c == quote => {
                    self.at += 1 + i + 1;
                    return Ok(text);
                }
                c => text.push(c),
            }
        }
        self.fail("an unclosed string")
    }

    fn or(&mut self) -> Result<Expr, String> {
        let mut left = self.and()?;
        while self.eat("||") {
            left = Expr::Binary("||", Box::new(left), Box::new(self.and()?));
        }
        Ok(left)
    }

    fn and(&mut self) -> Result<Expr, String> {
        let mut left = self.unary()?;
        while self.eat("&&") {
            left = Expr::Binary("&&", Box::new(left), Box::new(self.unary()?));
        }
        Ok(left)
    }

    fn unary(&mut self) -> Result<Expr, String> {
        if self.eat("!") {
            return Ok(Expr::Not(Box::new(self.unary()?)));
        }
        let left = self.operand()?;
        self.space();
        let op = OPERATORS[..8]
            .iter()
            .find(|op| self.rest().starts_with(**op));
        let Some(op) = op else {
            return Ok(left);
        };
        self.at += op.len();
        Ok(Expr::Binary(op, Box::new(left), Box::new(self.operand()?)))
    }

    fn operand(&mut self) -> Result<Expr, String> {
        self.space();
        if self.eat("(") {
            let inner = self.or()?;
            return match self.eat(")") {
                true => Ok(inner),
                false => self.fail("`)` expected"),
            };
        }
        for (start, from_root) in [("@", false), ("$", true)] {
            if self.eat(start) {
                return Ok(Expr::Path(from_root, self.path(false)?));
            }
        }
        if self.rest().starts_with('/') {
            return self.pattern();
        }
        if self.eat("[") {
            return self.list();
        }
        Ok(Expr::Literal(self.literal()?))
    }

    fn pattern(&mut self) -> Result<Expr, String> {
        let body = &self.rest()[1..];
        let mut escaped = false;
        let end = body.find(|c| {
            let close = c == '/' && !escaped;
            escaped = c == '\\' && !escaped;
            close
        });
        let Some(end) = end else {
            return self.fail("an unclosed regex");
        };
        let pattern = body[..end].replace("\\/", "/");
        self.at += end + 2;
        Regex::new(&pattern)
            .map(Expr::Pattern)
            .map_err(|e| e.to_string())
    }

    fn list(&mut self) -> Result<Expr, String> {
        let mut items = Vec::new();
        while !self.eat("]") {
            if !items.is_empty() && !self.eat(",") {
                return self.fail("`,` expected");
            }
            items.push(self.literal()?);
        }
        Ok(Expr::List(items))
    }

    fn literal(&mut self) -> Result<Json, String> {
        self.space();
        if self.rest().starts_with(['\'', '"']) {
            return Ok(Json::Str(self.quoted()?));
        }
        for (word, json) in [
            ("true", Json::Bool(true)),
            ("false", Json::Bool(false)),
            ("null", Json::Null),
        ] {
            if self.eat(word) {
                return Ok(json);
            }
        }
        let rest = self.rest();
        let end = rest
            .find(|c: char| !(c.is_ascii_digit() || "+-.eE".contains(c)))
            .unwrap_or(rest.len());
        match rest[..end].parse() {
            Ok(number) if end > 0 => {
                self.at += end;
                Ok(Json::Num(number))
            }
            _ => self.fail("a value expected"),
        }
    }
}

fn name_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_' || c == '-' || !c.is_ascii()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_paths() {
        let doc = Json::parse(
            r#"{"a":{"b":[{"c":1,"n":"x"},{"c":2,"n":"y"},{"c":3}]},
                "d":{"c":4},"lim":2}"#,
        )
        .unwrap();
        let found = |path: &str| {
            let found = find(&doc, path).unwrap();
            Json::Arr(found.into_iter().cloned().collect()).go_text()
        };
        assert_eq!(found("$.a.b[1].c"), "[2]");
        assert_eq!(found(".a.b[-1].c"), "[3]");
        assert_eq!(found("$..c"), "[1,2,3,4]");
        assert_eq!(found("$['d'].*"), "[4]");
        assert_eq!(found("$.x"), "[]");
        assert_eq!(found("$.a.b[0,2].c"), "[1,3]");
        assert_eq!(found("$.a.b[1:].c"), "[2,3]");
        assert_eq!(found("$.a.b[::-1].c"), "[3,2,1]");
        assert_eq!(found("$.a.b[?(@.c > 1)].c"), "[2,3]");
        assert_eq!(found("$.a.b[?(@.c < $.lim || @.n == 'y')].c"), "[1,2]");
        assert_eq!(found("$.a.b[?(@.n =~ /^[xy]$/ && !(@.c == 1))].c"), "[2]");
        assert_eq!(found("$.a.b[?(@.c in [1, 3])].c"), "[1,3]");
        assert_eq!(found("$.a.b[?(@.n)].c"), "[1,2]");
        assert!(find(&doc, "$.a[?(@.b").is_err());
    }
}
