//! Alloy's configuration syntax (grafana.com/docs/alloy, "Syntax"):
//! blocks with optional labels, attributes, and expressions with
//! literals, arrays, objects, references, calls and operators. Read
//! into a tree; what it means is crate::alloy::compile's.

use std::fmt;

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Pos {
    pub line: u32,
    pub col: u32,
}

impl fmt::Display for Pos {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}:{}", self.line, self.col)
    }
}

#[derive(Debug)]
pub struct Expr {
    pub kind: Kind,
    pub pos: Pos,
}

#[derive(Debug)]
pub enum Kind {
    Null,
    Bool(bool),
    /// A literal without a fraction or exponent, as Alloy's int.
    Int(i64),
    Number(f64),
    Str(String),
    Array(Vec<Expr>),
    Object(Vec<(String, Expr)>),
    Ident(String),
    Access(Box<Expr>, String),
    Index(Box<Expr>, Box<Expr>),
    Call(Box<Expr>, Vec<Expr>),
    Unary(&'static str, Box<Expr>),
    Binary(&'static str, Box<Expr>, Box<Expr>),
}

#[derive(Debug)]
pub enum Stmt {
    Attr { name: String, value: Expr, pos: Pos },
    Block(Block),
}

#[derive(Debug)]
pub struct Block {
    /// Dotted: `prometheus.exporter.unix`, `rule`, `stage.regex`.
    pub name: String,
    pub label: Option<String>,
    pub body: Vec<Stmt>,
    pub pos: Pos,
}

pub fn parse(text: &str) -> Result<Vec<Stmt>, String> {
    let tokens = lex(text)?;
    let mut parser = Parser { tokens, at: 0 };
    let body = parser.body()?;
    match parser.peek() {
        Token::End => Ok(body),
        other => Err(parser.error(&format!("unexpected {other}"))),
    }
}

#[derive(Clone, Debug, PartialEq)]
enum Token {
    Ident(String),
    Int(i64),
    Number(f64),
    Str(String),
    Punct(&'static str),
    End,
}

impl fmt::Display for Token {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Token::Ident(name) => write!(f, "`{name}`"),
            Token::Int(n) => write!(f, "number {n}"),
            Token::Number(n) => write!(f, "number {n}"),
            Token::Str(_) => write!(f, "a string"),
            Token::Punct(p) => write!(f, "`{p}`"),
            Token::End => write!(f, "end of file"),
        }
    }
}

/// Longest first, so `==` is not read as `=`.
const PUNCTS: [&str; 24] = [
    "==", "!=", "<=", ">=", "&&", "||", "=", "<", ">", "!", "+", "-", "*", "/",
    "%", "^", ".", ",", "(", ")", "[", "]", "{", "}",
];

fn lex(text: &str) -> Result<Vec<(Token, Pos)>, String> {
    let mut lexer = Lexer {
        chars: text.chars().collect(),
        at: 0,
        pos: Pos { line: 1, col: 1 },
    };
    let mut tokens = Vec::new();
    loop {
        lexer.skip_space()?;
        let pos = lexer.pos;
        let token = lexer.token().map_err(|e| format!("{pos}: {e}"))?;
        let end = token == Token::End;
        tokens.push((token, pos));
        if end {
            return Ok(tokens);
        }
    }
}

struct Lexer {
    chars: Vec<char>,
    at: usize,
    pos: Pos,
}

impl Lexer {
    fn peek(&self, ahead: usize) -> Option<char> {
        self.chars.get(self.at + ahead).copied()
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.peek(0)?;
        self.at += 1;
        if c == '\n' {
            self.pos.line += 1;
            self.pos.col = 1;
        } else {
            self.pos.col += 1;
        }
        Some(c)
    }

    fn skip_space(&mut self) -> Result<(), String> {
        loop {
            match (self.peek(0), self.peek(1)) {
                (Some(c), _) if c.is_whitespace() => drop(self.bump()),
                (Some('/'), Some('/')) | (Some('#'), _) => {
                    while self.peek(0).is_some_and(|c| c != '\n') {
                        self.bump();
                    }
                }
                (Some('/'), Some('*')) => {
                    let start = self.pos;
                    self.bump();
                    self.bump();
                    while (self.peek(0), self.peek(1)) != (Some('*'), Some('/'))
                    {
                        self.bump()
                            .ok_or(format!("{start}: unclosed comment"))?;
                    }
                    self.bump();
                    self.bump();
                }
                _ => return Ok(()),
            }
        }
    }

    // One arm per kind of token: longer than 40 lines, as a table is
    // read whole.
    fn token(&mut self) -> Result<Token, String> {
        let Some(c) = self.peek(0) else {
            return Ok(Token::End);
        };
        if c.is_alphabetic() || c == '_' {
            let mut name = String::new();
            while self
                .peek(0)
                .is_some_and(|c| c.is_alphanumeric() || c == '_')
            {
                name.extend(self.bump());
            }
            return Ok(Token::Ident(name));
        }
        if c.is_ascii_digit() {
            return self.number();
        }
        if c == '"' {
            return self.string();
        }
        if c == '`' {
            self.bump();
            let mut text = String::new();
            loop {
                match self.bump() {
                    Some('`') => return Ok(Token::Str(text)),
                    Some(c) => text.push(c),
                    None => return Err("unclosed raw string".into()),
                }
            }
        }
        for punct in PUNCTS {
            let fits = punct
                .chars()
                .enumerate()
                .all(|(i, p)| self.peek(i) == Some(p));
            if fits {
                punct.chars().for_each(|_| {
                    self.bump();
                });
                return Ok(Token::Punct(punct));
            }
        }
        Err(format!("unexpected `{c}`"))
    }

    fn number(&mut self) -> Result<Token, String> {
        let mut text = String::new();
        while let Some(c) = self.peek(0) {
            let sign = (c == '+' || c == '-')
                && text.ends_with(['e', 'E'])
                && !text.starts_with("0x");
            if c.is_ascii_alphanumeric() || c == '.' || c == '_' || sign {
                // A `.` not followed by a digit is an access: `1.x`.
                if c == '.' && !self.peek(1).is_some_and(|d| d.is_ascii_digit())
                {
                    break;
                }
                text.extend(self.bump());
            } else {
                break;
            }
        }
        let clean = text.replace('_', "");
        let int = match clean.strip_prefix("0x") {
            Some(hex) => i64::from_str_radix(hex, 16).ok(),
            None => clean.parse().ok(),
        };
        // shortcut: an integer past i64 is a float here, a uint in Alloy;
        // add a uint kind if a config needs such numbers exact.
        let value = int
            .map(Token::Int)
            .or_else(|| clean.parse().ok().map(Token::Number));
        value.ok_or_else(|| format!("bad number `{text}`"))
    }

    fn string(&mut self) -> Result<Token, String> {
        self.bump();
        let mut text = String::new();
        loop {
            match self.bump() {
                Some('"') => return Ok(Token::Str(text)),
                Some('\\') => text.push(self.escape()?),
                Some('\n') | None => return Err("unclosed string".into()),
                Some(c) => text.push(c),
            }
        }
    }

    /// Go's escapes, as Alloy's strings take them.
    fn escape(&mut self) -> Result<char, String> {
        let hex = |lexer: &mut Lexer, digits: usize| {
            let code: String =
                (0..digits).filter_map(|_| lexer.bump()).collect();
            u32::from_str_radix(&code, 16)
                .ok()
                .and_then(char::from_u32)
                .ok_or(format!("bad escape `{code}`"))
        };
        Ok(match self.bump() {
            Some('n') => '\n',
            Some('t') => '\t',
            Some('r') => '\r',
            Some('a') => '\x07',
            Some('b') => '\x08',
            Some('f') => '\x0c',
            Some('v') => '\x0b',
            Some(c @ ('\\' | '"' | '\'')) => c,
            Some('x') => hex(self, 2)?,
            Some('u') => hex(self, 4)?,
            Some('U') => hex(self, 8)?,
            other => return Err(format!("unknown escape {other:?}")),
        })
    }
}

struct Parser {
    tokens: Vec<(Token, Pos)>,
    at: usize,
}

/// Binary operators by precedence, loosest first.
const LEVELS: [&[&str]; 6] = [
    &["||"],
    &["&&"],
    &["==", "!=", "<", "<=", ">", ">="],
    &["+", "-"],
    &["*", "/", "%"],
    &["^"],
];

impl Parser {
    fn peek(&self) -> &Token {
        &self.tokens[self.at].0
    }

    fn pos(&self) -> Pos {
        self.tokens[self.at].1
    }

    fn next(&mut self) -> Token {
        let token = self.tokens[self.at].0.clone();
        if token != Token::End {
            self.at += 1;
        }
        token
    }

    fn error(&self, message: &str) -> String {
        format!("{}: {message}", self.pos())
    }

    fn eat(&mut self, punct: &str) -> bool {
        let found = matches!(self.peek(), Token::Punct(p) if *p == punct);
        if found {
            self.at += 1;
        }
        found
    }

    fn expect(&mut self, punct: &str) -> Result<(), String> {
        if self.eat(punct) {
            return Ok(());
        }
        Err(self.error(&format!("expected `{punct}`, found {}", self.peek())))
    }

    /// Statements up to `}` or the end.
    fn body(&mut self) -> Result<Vec<Stmt>, String> {
        let mut body = Vec::new();
        while let Token::Ident(_) = self.peek() {
            body.push(self.stmt()?);
        }
        Ok(body)
    }

    fn stmt(&mut self) -> Result<Stmt, String> {
        let pos = self.pos();
        let Token::Ident(mut name) = self.next() else {
            unreachable!("body checks for an identifier");
        };
        if self.eat("=") {
            let value = self.expr(0)?;
            return Ok(Stmt::Attr { name, value, pos });
        }
        while self.eat(".") {
            match self.next() {
                Token::Ident(part) => name = format!("{name}.{part}"),
                other => return Err(self.error(&format!("unexpected {other}"))),
            }
        }
        let label = match self.peek() {
            Token::Str(label) => Some(label.clone()),
            _ => None,
        };
        if label.is_some() {
            self.at += 1;
        }
        self.expect("{")?;
        let body = self.body()?;
        self.expect("}")?;
        Ok(Stmt::Block(Block {
            name,
            label,
            body,
            pos,
        }))
    }

    fn expr(&mut self, level: usize) -> Result<Expr, String> {
        let Some(ops) = LEVELS.get(level) else {
            return self.unary();
        };
        let mut left = self.expr(level + 1)?;
        loop {
            let op = match self.peek() {
                Token::Punct(p) => ops.iter().find(|o| *o == p).copied(),
                _ => None,
            };
            let Some(op) = op else {
                return Ok(left);
            };
            let pos = self.pos();
            self.at += 1;
            // `^` binds to the right; the others to the left.
            let right = self.expr(level + usize::from(op != "^"))?;
            let kind = Kind::Binary(op, Box::new(left), Box::new(right));
            left = Expr { kind, pos };
        }
    }

    fn unary(&mut self) -> Result<Expr, String> {
        let pos = self.pos();
        for op in ["!", "-"] {
            if self.eat(op) {
                let operand = Box::new(self.unary()?);
                return Ok(Expr {
                    kind: Kind::Unary(op, operand),
                    pos,
                });
            }
        }
        let mut expr = self.primary()?;
        loop {
            let pos = self.pos();
            let kind = if self.eat(".") {
                match self.next() {
                    Token::Ident(field) => Kind::Access(Box::new(expr), field),
                    other => {
                        return Err(self.error(&format!("unexpected {other}")));
                    }
                }
            } else if self.eat("[") {
                let index = self.expr(0)?;
                self.expect("]")?;
                Kind::Index(Box::new(expr), Box::new(index))
            } else if self.eat("(") {
                let args = self.list(")")?;
                Kind::Call(Box::new(expr), args)
            } else {
                return Ok(expr);
            };
            expr = Expr { kind, pos };
        }
    }

    fn primary(&mut self) -> Result<Expr, String> {
        let pos = self.pos();
        let kind = match self.next() {
            Token::Int(n) => Kind::Int(n),
            Token::Number(n) => Kind::Number(n),
            Token::Str(s) => Kind::Str(s),
            Token::Ident(name) => match name.as_str() {
                "null" => Kind::Null,
                "true" => Kind::Bool(true),
                "false" => Kind::Bool(false),
                _ => Kind::Ident(name),
            },
            Token::Punct("(") => {
                let inner = self.expr(0)?;
                self.expect(")")?;
                return Ok(inner);
            }
            Token::Punct("[") => Kind::Array(self.list("]")?),
            Token::Punct("{") => Kind::Object(self.object()?),
            other => return Err(format!("{pos}: unexpected {other}")),
        };
        Ok(Expr { kind, pos })
    }

    /// Expressions separated by commas, a trailing one allowed.
    fn list(&mut self, close: &str) -> Result<Vec<Expr>, String> {
        let mut items = Vec::new();
        while !self.eat(close) {
            items.push(self.expr(0)?);
            if !self.eat(",") {
                self.expect(close)?;
                break;
            }
        }
        Ok(items)
    }

    fn object(&mut self) -> Result<Vec<(String, Expr)>, String> {
        let mut fields = Vec::new();
        while !self.eat("}") {
            let key = match self.next() {
                Token::Ident(key) | Token::Str(key) => key,
                other => return Err(self.error(&format!("unexpected {other}"))),
            };
            self.expect("=")?;
            fields.push((key, self.expr(0)?));
            if !self.eat(",") {
                self.expect("}")?;
                break;
            }
        }
        Ok(fields)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_blocks_attributes_and_expressions() {
        let text = r#"
            // comment
            prometheus.scrape "node" {
              targets = discovery.relabel.node.output
              interval = 1 + 2 * 3 ^ 2
              rule { regex = `a"b` }
              labels = { job = "x", "a.b" = [1, -2.5,] }
            }
            /* block comment */
            logging { level = sys.env("LEVEL") }
        "#;
        let body = parse(text).unwrap();
        let Stmt::Block(block) = &body[0] else {
            panic!("not a block");
        };
        assert_eq!(block.name, "prometheus.scrape");
        assert_eq!(block.label.as_deref(), Some("node"));
        assert_eq!(block.body.len(), 4);
        let Stmt::Attr { value, .. } = &block.body[1] else {
            panic!("not an attribute");
        };
        assert!(matches!(value.kind, Kind::Binary("+", _, _)));
        let Stmt::Block(rule) = &block.body[2] else {
            panic!("not a block");
        };
        assert!(matches!(&rule.body[0],
            Stmt::Attr { value: Expr { kind: Kind::Str(s), .. }, .. }
            if s == "a\"b"));
    }

    #[test]
    fn says_where_it_fails() {
        let error = parse("a {\n  b = \n}").unwrap_err();
        assert_eq!(error, "3:1: unexpected `}`");
        assert!(parse("x = \"\\q\"").unwrap_err().contains("escape"));
    }
}
