//! The part of Go's text/template that loki.process's template and
//! replace stages are written in: text, `{{ }}` actions holding a
//! pipeline of commands (`.Value | ToLower`, `Replace .Value "a" "b"
//! -1`), fields of the extracted map, string and number literals, and
//! the string functions Promtail gives templates.

pub struct Template(Vec<Piece>);

enum Piece {
    Text(String),
    /// Commands joined by `|`: each one's result is the next's last
    /// argument.
    Action(Vec<Vec<Arg>>),
}

#[derive(Clone)]
enum Arg {
    /// `.Value`, `.level`.
    Field(String),
    Str(String),
    Number(i64),
    Function(String),
}

/// Looks up a field: `.Value`, `.Entry`, or an extracted value.
pub type Fields<'a> = &'a dyn Fn(&str) -> Option<String>;

impl Template {
    pub fn parse(text: &str) -> Result<Template, String> {
        let mut pieces = Vec::new();
        let mut rest = text;
        while let Some(open) = rest.find("{{") {
            pieces.push(Piece::Text(rest[..open].to_owned()));
            let inner = &rest[open + 2..];
            let close = inner.find("}}").ok_or("`{{` without `}}`")?;
            let action = inner[..close].trim_matches(['-', ' ']);
            pieces.push(Piece::Action(pipeline(action)?));
            rest = &inner[close + 2..];
        }
        pieces.push(Piece::Text(rest.to_owned()));
        Ok(Template(pieces))
    }

    /// The text, or why an action failed (a missing field passed on).
    pub fn render(&self, fields: Fields) -> Result<String, String> {
        let mut out = String::new();
        for piece in &self.0 {
            match piece {
                Piece::Text(text) => out.push_str(text),
                Piece::Action(commands) => {
                    let value = run(commands, fields)?;
                    out.push_str(value.as_deref().unwrap_or("<no value>"));
                }
            }
        }
        Ok(out)
    }
}

fn pipeline(action: &str) -> Result<Vec<Vec<Arg>>, String> {
    let mut commands = Vec::new();
    let mut command = Vec::new();
    let mut rest = action.trim();
    while !rest.is_empty() {
        if let Some(after) = rest.strip_prefix('|') {
            commands.push(std::mem::take(&mut command));
            rest = after.trim_start();
            continue;
        }
        let (arg, after) = word(rest)?;
        command.push(arg);
        rest = after.trim_start();
    }
    commands.push(command);
    if commands.iter().any(Vec::is_empty) {
        return Err(format!("empty command in `{action}`"));
    }
    Ok(commands)
}

/// The next argument and what follows it.
fn word(text: &str) -> Result<(Arg, &str), String> {
    if let Some(quoted) = text.strip_prefix('"') {
        let end = quoted.find('"').ok_or("unclosed string")?;
        let value = quoted[..end].replace("\\n", "\n").replace("\\t", "\t");
        return Ok((Arg::Str(value), &quoted[end + 1..]));
    }
    if let Some(raw) = text.strip_prefix('`') {
        let end = raw.find('`').ok_or("unclosed string")?;
        return Ok((Arg::Str(raw[..end].to_owned()), &raw[end + 1..]));
    }
    let end = text.find([' ', '|']).unwrap_or(text.len());
    let (token, rest) = text.split_at(end);
    let arg = match token.strip_prefix('.') {
        Some(field) => Arg::Field(field.to_owned()),
        None => match token.parse() {
            Ok(number) => Arg::Number(number),
            Err(_) => Arg::Function(token.to_owned()),
        },
    };
    Ok((arg, rest))
}

fn run(
    commands: &[Vec<Arg>],
    fields: Fields,
) -> Result<Option<String>, String> {
    let mut piped: Option<Option<String>> = None;
    for command in commands {
        let mut args: Vec<Option<String>> = Vec::new();
        for arg in &command[1..] {
            args.push(value(arg, fields));
        }
        args.extend(piped.take());
        piped = Some(match &command[0] {
            Arg::Function(name) => Some(call(name, &args)?),
            first if args.is_empty() => value(first, fields),
            _ => return Err("arguments to a non-function".into()),
        });
    }
    Ok(piped.flatten())
}

fn value(arg: &Arg, fields: Fields) -> Option<String> {
    match arg {
        Arg::Field(name) => fields(name),
        Arg::Str(text) => Some(text.clone()),
        Arg::Number(number) => Some(number.to_string()),
        Arg::Function(_) => None,
    }
}

fn call(name: &str, args: &[Option<String>]) -> Result<String, String> {
    let args: Vec<&str> = args
        .iter()
        .map(|a| a.as_deref().ok_or("a missing value passed on"))
        .collect::<Result<_, _>>()?;
    Ok(match (name, &args[..]) {
        ("ToLower", [s]) => s.to_lowercase(),
        ("ToUpper", [s]) => s.to_uppercase(),
        ("TrimSpace", [s]) => s.trim().to_owned(),
        ("Trim", [s, cut]) => s.trim_matches(|c| cut.contains(c)).to_owned(),
        ("TrimLeft", [s, cut]) => {
            s.trim_start_matches(|c| cut.contains(c)).to_owned()
        }
        ("TrimRight", [s, cut]) => {
            s.trim_end_matches(|c| cut.contains(c)).to_owned()
        }
        ("TrimPrefix", [s, p]) => s.strip_prefix(p).unwrap_or(s).to_owned(),
        ("TrimSuffix", [s, p]) => s.strip_suffix(p).unwrap_or(s).to_owned(),
        ("Replace", [s, old, new, n]) => {
            let n: i64 = n.parse().map_err(|_| "Replace's count")?;
            match usize::try_from(n) {
                Ok(n) => s.replacen(old, new, n),
                Err(_) => s.replace(old, new),
            }
        }
        _ => return Err(format!("{name} with {} arguments", args.len())),
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
        Template::parse(text).unwrap().render(&fields)
    }

    #[test]
    fn renders_pipelines_and_calls() {
        assert_eq!(render("{{ ToLower .Value }}").unwrap(), "warn");
        assert_eq!(render("{{ .Value | ToUpper }}!").unwrap(), "WARN!");
        let replaced = render(r#"{{ Replace .app "n" "N" -1 }}"#).unwrap();
        assert_eq!(replaced, "Ndm");
        assert_eq!(render("a {{ .nope }}").unwrap(), "a <no value>");
        assert!(render("{{ ToLower .nope }}").is_err());
    }
}
