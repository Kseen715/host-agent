//! Go's text/template as loki.process's template and replace stages
//! use it: text, `{{ }}` actions holding a pipeline of commands
//! (`.Value | ToLower`), fields of the extracted map, literals,
//! parentheses, `if`/`else if`/`else`/`end`, comments and the `{{-`
//! `-}}` trims; the functions are functions.rs's. Variables, `range`,
//! `with` and the like are refused when parsed.

mod functions;

pub use functions::{Val, printf};

pub struct Template(Vec<Node>);

enum Node {
    Text(String),
    Action(Pipeline),
    /// The `if` and `else if` branches, then what `else` holds.
    If(Vec<(Pipeline, Vec<Node>)>, Vec<Node>),
}

/// Commands joined by `|`: each one's result is the next's last
/// argument.
type Pipeline = Vec<Vec<Arg>>;

#[derive(Clone)]
enum Arg {
    /// `.Value`, `.level`.
    Field(String),
    Literal(Val),
    Function(String),
    Group(Pipeline),
}

/// Looks up a field: `.Value`, `.Entry`, or an extracted value.
pub type Fields<'a> = &'a dyn Fn(&str) -> Option<String>;

enum Token {
    Text(String),
    Action(String),
}

enum Ending {
    Eof,
    End,
    /// `else`, and what follows it: `if <pipeline>` or nothing.
    Else(String),
}

const UNSUPPORTED: [&str; 7] = [
    "range", "with", "define", "template", "block", "break", "continue",
];

impl Template {
    pub fn parse(text: &str) -> Result<Template, String> {
        let mut tokens = tokens(text)?.into_iter();
        match block(&mut tokens)? {
            (nodes, Ending::Eof) => Ok(Template(nodes)),
            (_, Ending::End) => Err("unexpected {{end}}".into()),
            (_, Ending::Else(_)) => Err("unexpected {{else}}".into()),
        }
    }

    /// The text, or why an action failed (a missing field passed on).
    pub fn render(&self, fields: Fields) -> Result<String, String> {
        let mut out = String::new();
        render(&self.0, fields, &mut out)?;
        Ok(out)
    }
}

fn render(
    nodes: &[Node],
    fields: Fields,
    out: &mut String,
) -> Result<(), String> {
    for node in nodes {
        match node {
            Node::Text(text) => out.push_str(text),
            Node::Action(pipeline) => {
                out.push_str(&run(pipeline, fields)?.text())
            }
            Node::If(branches, otherwise) => {
                let mut chosen = otherwise;
                for (condition, body) in branches {
                    if run(condition, fields)?.truth() {
                        chosen = body;
                        break;
                    }
                }
                render(chosen, fields, out)?;
            }
        }
    }
    Ok(())
}

/// Text and actions, trimmed where `{{- ` and ` -}}` say; comments
/// left out.
fn tokens(text: &str) -> Result<Vec<Token>, String> {
    let mut tokens = Vec::new();
    let (mut rest, mut trim_next) = (text, false);
    while let Some(open) = rest.find("{{") {
        let mut before = &rest[..open];
        if trim_next {
            before = before.trim_start();
        }
        let inner = &rest[open + 2..];
        let trim_before = inner.starts_with("- ") || inner.starts_with("-\n");
        if trim_before {
            before = before.trim_end();
        }
        tokens.push(Token::Text(before.to_owned()));
        let close = action_end(inner).ok_or("`{{` without `}}`")?;
        let action = &inner[..close];
        trim_next = action.ends_with(" -") || action.ends_with("\n-");
        let action = action
            .strip_prefix('-')
            .filter(|_| trim_before)
            .unwrap_or(action);
        let action = match trim_next {
            true => &action[..action.len() - 1],
            false => action,
        };
        let action = action.trim();
        if !(action.starts_with("/*") && action.ends_with("*/")) {
            tokens.push(Token::Action(action.to_owned()));
        }
        rest = &inner[close + 2..];
    }
    let rest = if trim_next { rest.trim_start() } else { rest };
    tokens.push(Token::Text(rest.to_owned()));
    Ok(tokens)
}

/// Where `}}` ends an action, past strings that may hold it.
fn action_end(inner: &str) -> Option<usize> {
    let bytes = inner.as_bytes();
    let mut quote = None;
    let mut at = 0;
    while at < bytes.len() {
        match (quote, bytes[at]) {
            (None, b'"' | b'`') => quote = Some(bytes[at]),
            (Some(b'"'), b'\\') => at += 1,
            (Some(q), c) if c == q => quote = None,
            (None, b'}') if bytes.get(at + 1) == Some(&b'}') => {
                return Some(at);
            }
            _ => {}
        }
        at += 1;
    }
    None
}

fn block(
    tokens: &mut std::vec::IntoIter<Token>,
) -> Result<(Vec<Node>, Ending), String> {
    let mut nodes = Vec::new();
    while let Some(token) = tokens.next() {
        let action = match token {
            Token::Text(text) => {
                nodes.push(Node::Text(text));
                continue;
            }
            Token::Action(action) => action,
        };
        let (keyword, rest) = action
            .split_once(char::is_whitespace)
            .unwrap_or((&action, ""));
        match keyword {
            "if" => nodes.push(if_node(pipeline(rest)?, tokens)?),
            "else" => return Ok((nodes, Ending::Else(rest.trim().to_owned()))),
            "end" => return Ok((nodes, Ending::End)),
            _ if UNSUPPORTED.contains(&keyword) => {
                return Err(format!("`{keyword}` is not supported here"));
            }
            _ => nodes.push(Node::Action(pipeline(&action)?)),
        }
    }
    Ok((nodes, Ending::Eof))
}

fn if_node(
    mut condition: Pipeline,
    tokens: &mut std::vec::IntoIter<Token>,
) -> Result<Node, String> {
    let mut branches = Vec::new();
    loop {
        let (body, ending) = block(tokens)?;
        branches.push((condition, body));
        match ending {
            Ending::End => return Ok(Node::If(branches, Vec::new())),
            Ending::Eof => return Err("`if` without `end`".into()),
            Ending::Else(rest) if rest.is_empty() => {
                let (otherwise, ending) = block(tokens)?;
                let Ending::End = ending else {
                    return Err("`else` without `end`".into());
                };
                return Ok(Node::If(branches, otherwise));
            }
            Ending::Else(rest) => match rest.strip_prefix("if") {
                Some(more) if more.starts_with(char::is_whitespace) => {
                    condition = pipeline(more)?;
                }
                _ => return Err(format!("unexpected `else {rest}`")),
            },
        }
    }
}

fn pipeline(text: &str) -> Result<Pipeline, String> {
    let (pipeline, rest) = commands(text)?;
    match rest.trim().is_empty() {
        true => Ok(pipeline),
        false => Err(format!("unexpected `{rest}`")),
    }
}

/// Commands up to the end or a `)`, and what is left.
fn commands(text: &str) -> Result<(Pipeline, &str), String> {
    let mut found = Vec::new();
    let mut command = Vec::new();
    let mut rest = text.trim_start();
    while !rest.is_empty() && !rest.starts_with(')') {
        if let Some(after) = rest.strip_prefix('|') {
            found.push(std::mem::take(&mut command));
            rest = after.trim_start();
            continue;
        }
        let (arg, after) = match rest.strip_prefix('(') {
            Some(inner) => {
                let (group, after) = commands(inner)?;
                let after = after.strip_prefix(')').ok_or("unclosed `(`")?;
                (Arg::Group(group), after)
            }
            None => word(rest)?,
        };
        command.push(arg);
        rest = after.trim_start();
    }
    found.push(command);
    if found.iter().any(Vec::is_empty) {
        return Err(format!("missing command in `{}`", text.trim()));
    }
    Ok((found, rest))
}

/// The next argument and what follows it.
fn word(text: &str) -> Result<(Arg, &str), String> {
    if text.starts_with('"') {
        let (value, rest) = unquote(text)?;
        return Ok((Arg::Literal(Val::Str(value)), rest));
    }
    if let Some(raw) = text.strip_prefix('`') {
        let end = raw.find('`').ok_or("unclosed raw string")?;
        let value = Val::Str(raw[..end].to_owned());
        return Ok((Arg::Literal(value), &raw[end + 1..]));
    }
    let end = text
        .find(|c: char| c.is_whitespace() || matches!(c, '|' | '(' | ')'))
        .unwrap_or(text.len());
    let (token, rest) = text.split_at(end);
    let arg = match token {
        "." => return Err("`.` alone is not supported here".into()),
        "true" | "false" => Arg::Literal(Val::Bool(token == "true")),
        _ if token.starts_with('$') => {
            return Err("variables are not supported here".into());
        }
        _ if token.starts_with('.') => Arg::Field(token[1..].to_owned()),
        _ => match number(token) {
            Some(value) => Arg::Literal(value),
            None if functions::known(token) => Arg::Function(token.to_owned()),
            None => return Err(format!("function \"{token}\" not defined")),
        },
    };
    Ok((arg, rest))
}

fn number(token: &str) -> Option<Val> {
    let (negative, digits) = match token.strip_prefix('-') {
        Some(digits) => (true, digits),
        None => (false, token.strip_prefix('+').unwrap_or(token)),
    };
    let int = match digits.strip_prefix("0x").or(digits.strip_prefix("0X")) {
        Some(hex) => i64::from_str_radix(hex, 16).ok(),
        None => digits.parse::<i64>().ok(),
    };
    match int {
        Some(int) => Some(Val::Int(if negative { -int } else { int })),
        None if token
            .starts_with(|c: char| c.is_ascii_digit() || "+-.".contains(c)) =>
        {
            token.parse().ok().map(Val::Float)
        }
        None => None,
    }
}

/// A Go double-quoted string at the start of `text`, and what follows.
fn unquote(text: &str) -> Result<(String, &str), String> {
    let mut value = String::new();
    let mut chars = text[1..].char_indices();
    while let Some((at, c)) = chars.next() {
        match c {
            '"' => return Ok((value, &text[at + 2..])),
            '\\' => {
                let (_, escaped) = chars.next().ok_or("unclosed string")?;
                value.push(match escaped {
                    'n' => '\n',
                    't' => '\t',
                    'r' => '\r',
                    '0' => '\0',
                    other => other,
                });
            }
            c => value.push(c),
        }
    }
    Err("unclosed string".into())
}

fn run(pipeline: &Pipeline, fields: Fields) -> Result<Val, String> {
    let mut piped: Option<Val> = None;
    for command in pipeline {
        let value = match &command[0] {
            Arg::Function(name) if name == "and" || name == "or" => {
                logic(name == "and", &command[1..], piped.take(), fields)?
            }
            Arg::Function(name) => {
                let mut args = Vec::new();
                for arg in &command[1..] {
                    args.push(eval(arg, fields)?);
                }
                args.extend(piped.take());
                functions::call(name, args)?
            }
            first if command.len() == 1 && piped.is_none() => {
                eval(first, fields)?
            }
            _ => return Err("can't give argument to non-function".into()),
        };
        piped = Some(value);
    }
    Ok(piped.unwrap_or(Val::Nil))
}

/// `and` and `or`, which stop at the first argument that decides.
fn logic(
    and: bool,
    args: &[Arg],
    piped: Option<Val>,
    fields: Fields,
) -> Result<Val, String> {
    let mut last = Val::Nil;
    for arg in args {
        last = eval(arg, fields)?;
        if last.truth() != and {
            return Ok(last);
        }
    }
    Ok(piped.unwrap_or(last))
}

fn eval(arg: &Arg, fields: Fields) -> Result<Val, String> {
    Ok(match arg {
        Arg::Field(name) => fields(name).map_or(Val::Nil, Val::Str),
        Arg::Literal(value) => value.clone(),
        Arg::Function(name) => functions::call(name, Vec::new())?,
        Arg::Group(pipeline) => run(pipeline, fields)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn render(text: &str) -> Result<String, String> {
        let fields = |name: &str| match name {
            "Value" => Some("WaRN".to_owned()),
            "app" => Some("ndm".to_owned()),
            _ => None,
        };
        Template::parse(text)?.render(&fields)
    }

    #[test]
    fn renders_pipelines_and_calls() {
        assert_eq!(render("{{ ToLower .Value }}").unwrap(), "warn");
        assert_eq!(render("{{ .Value | ToUpper }}!").unwrap(), "WARN!");
        let replaced = render(r#"{{ Replace .app "n" "N" -1 }}"#).unwrap();
        assert_eq!(replaced, "Ndm");
        assert_eq!(render("a {{ .nope }}").unwrap(), "a <no value>");
        assert!(render("{{ ToLower .nope }}").is_err());
        assert!(
            render("{{ nosuch .app }}")
                .unwrap_err()
                .contains("not defined")
        );
    }

    #[test]
    fn renders_conditions() {
        let text = r#"{{ if eq (ToLower .Value) "warn" -}}
            warning
            {{- else if .app }}{{ .app }}{{ else }}none{{ end }}"#;
        assert_eq!(render(text).unwrap(), "warning");
        let text = r#"{{ if and .nope (eq .nope "x") }}a{{ else }}b{{ end }}"#;
        assert_eq!(render(text).unwrap(), "b");
        assert_eq!(
            render("{{/* note */}}x{{- \" }}\" -}} y").unwrap(),
            "x }}y"
        );
        let printf = r#"{{ printf "%s=%05d %.2f %q" .app 42 1.5 "a" }}"#;
        assert_eq!(render(printf).unwrap(), r#"ndm=00042 1.50 "a""#);
        assert_eq!(render(r#"{{ default "x" .nope | upper }}"#).unwrap(), "X");
        assert!(render("{{ range .x }}{{ end }}").is_err());
        assert!(render("{{ if .app }}").is_err());
    }
}
