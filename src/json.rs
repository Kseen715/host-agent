//! Just enough JSON: Docker's API answers and file_sd target lists are
//! read into a tree, Loki's push body is written with `escape`.

pub enum Json {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

const MAX_DEPTH: usize = 64;

impl Json {
    pub fn parse(text: &str) -> Option<Json> {
        let mut parser = Parser {
            bytes: text.as_bytes(),
            at: 0,
        };
        let value = parser.value(0)?;
        parser.skip_space();
        (parser.at == parser.bytes.len()).then_some(value)
    }

    pub fn get(&self, key: &str) -> Option<&Json> {
        self.obj().iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    pub fn str(&self) -> Option<&str> {
        match self {
            Json::Str(text) => Some(text),
            _ => None,
        }
    }

    pub fn num(&self) -> Option<f64> {
        match self {
            Json::Num(number) => Some(*number),
            _ => None,
        }
    }

    pub fn bool(&self) -> bool {
        matches!(self, Json::Bool(true))
    }

    pub fn arr(&self) -> &[Json] {
        match self {
            Json::Arr(items) => items,
            _ => &[],
        }
    }

    pub fn obj(&self) -> &[(String, Json)] {
        match self {
            Json::Obj(members) => members,
            _ => &[],
        }
    }
}

struct Parser<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Parser<'_> {
    fn value(&mut self, depth: usize) -> Option<Json> {
        if depth > MAX_DEPTH {
            return None;
        }
        self.skip_space();
        match *self.bytes.get(self.at)? {
            b'{' => self.object(depth),
            b'[' => self.array(depth),
            b'"' => self.string().map(Json::Str),
            b't' => self.word("true", Json::Bool(true)),
            b'f' => self.word("false", Json::Bool(false)),
            b'n' => self.word("null", Json::Null),
            _ => self.number(),
        }
    }

    fn object(&mut self, depth: usize) -> Option<Json> {
        self.at += 1;
        let mut members = Vec::new();
        if self.peek_after_space() == Some(b'}') {
            self.at += 1;
            return Some(Json::Obj(members));
        }
        loop {
            self.skip_space();
            let key = self.string()?;
            self.expect(b':')?;
            members.push((key, self.value(depth + 1)?));
            match self.next_after_space()? {
                b',' => continue,
                b'}' => return Some(Json::Obj(members)),
                _ => return None,
            }
        }
    }

    fn array(&mut self, depth: usize) -> Option<Json> {
        self.at += 1;
        let mut items = Vec::new();
        if self.peek_after_space() == Some(b']') {
            self.at += 1;
            return Some(Json::Arr(items));
        }
        loop {
            items.push(self.value(depth + 1)?);
            match self.next_after_space()? {
                b',' => continue,
                b']' => return Some(Json::Arr(items)),
                _ => return None,
            }
        }
    }

    fn string(&mut self) -> Option<String> {
        if self.bytes.get(self.at) != Some(&b'"') {
            return None;
        }
        self.at += 1;
        let mut out = Vec::new();
        loop {
            let byte = *self.bytes.get(self.at)?;
            self.at += 1;
            match byte {
                b'"' => return String::from_utf8(out).ok(),
                b'\\' => self.escape(&mut out)?,
                _ => out.push(byte),
            }
        }
    }

    fn escape(&mut self, out: &mut Vec<u8>) -> Option<()> {
        let byte = *self.bytes.get(self.at)?;
        self.at += 1;
        let simple = match byte {
            b'"' | b'\\' | b'/' => byte,
            b'b' => 8,
            b'f' => 12,
            b'n' => b'\n',
            b'r' => b'\r',
            b't' => b'\t',
            b'u' => {
                let ch = self.unicode()?;
                out.extend_from_slice(ch.encode_utf8(&mut [0; 4]).as_bytes());
                return Some(());
            }
            _ => return None,
        };
        out.push(simple);
        Some(())
    }

    /// `\uXXXX`, a surrogate pair as one character; a lone surrogate
    /// becomes U+FFFD.
    fn unicode(&mut self) -> Option<char> {
        let high = self.hex4()?;
        if !(0xD800..0xDC00).contains(&high) {
            return Some(char::from_u32(high).unwrap_or('\u{FFFD}'));
        }
        if self.bytes.get(self.at..self.at + 2) != Some(b"\\u") {
            return Some('\u{FFFD}');
        }
        self.at += 2;
        let low = self.hex4()?;
        let code =
            0x10000 + ((high - 0xD800) << 10) + (low.wrapping_sub(0xDC00));
        Some(char::from_u32(code).unwrap_or('\u{FFFD}'))
    }

    fn hex4(&mut self) -> Option<u32> {
        let digits = self.bytes.get(self.at..self.at + 4)?;
        self.at += 4;
        u32::from_str_radix(std::str::from_utf8(digits).ok()?, 16).ok()
    }

    fn number(&mut self) -> Option<Json> {
        let start = self.at;
        let is_number = |b: &u8| b"+-.eE0123456789".contains(b);
        while self.bytes.get(self.at).is_some_and(is_number) {
            self.at += 1;
        }
        let text = std::str::from_utf8(&self.bytes[start..self.at]).ok()?;
        text.parse().ok().map(Json::Num)
    }

    fn word(&mut self, word: &str, value: Json) -> Option<Json> {
        let end = self.at + word.len();
        if self.bytes.get(self.at..end) != Some(word.as_bytes()) {
            return None;
        }
        self.at = end;
        Some(value)
    }

    fn expect(&mut self, byte: u8) -> Option<()> {
        (self.next_after_space()? == byte).then_some(())
    }

    fn next_after_space(&mut self) -> Option<u8> {
        let byte = self.peek_after_space()?;
        self.at += 1;
        Some(byte)
    }

    fn peek_after_space(&mut self) -> Option<u8> {
        self.skip_space();
        self.bytes.get(self.at).copied()
    }

    fn skip_space(&mut self) {
        while self.bytes.get(self.at).is_some_and(u8::is_ascii_whitespace) {
            self.at += 1;
        }
    }
}

/// Appends `text` as the inside of a JSON string.
impl Json {
    /// As Go's encoding/json writes it: compact, keys sorted, `<>&`
    /// escaped.
    pub fn go_text(&self) -> String {
        let mut out = String::new();
        self.go_write(&mut out);
        out
    }

    fn go_write(&self, out: &mut String) {
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Json::Num(n) => out.push_str(&go_float(*n)),
            Json::Str(s) => go_string(out, s),
            Json::Arr(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    item.go_write(out);
                }
                out.push(']');
            }
            Json::Obj(fields) => {
                let mut sorted: Vec<_> = fields.iter().collect();
                sorted.sort_by(|a, b| a.0.cmp(&b.0));
                out.push('{');
                for (i, (key, value)) in sorted.into_iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    go_string(out, key);
                    out.push(':');
                    value.go_write(out);
                }
                out.push('}');
            }
        }
    }
}

fn go_string(out: &mut String, text: &str) {
    out.push('"');
    for ch in text.chars() {
        match ch {
            '<' | '>' | '&' | '\u{2028}' | '\u{2029}' => {
                out.push_str(&format!("\\u{:04x}", ch as u32));
            }
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c => escape(out, c.encode_utf8(&mut [0; 4])),
        }
    }
    out.push('"');
}

/// A float as Go's encoding/json writes it: decimal between 1e-6 and
/// 1e21, else `1e+21`, `1e-7`.
fn go_float(n: f64) -> String {
    let abs = n.abs();
    if abs == 0.0 || (1e-6..1e21).contains(&abs) {
        return format!("{n}");
    }
    let text = format!("{n:e}");
    match text.split_once('e') {
        Some((mantissa, exp)) if !exp.starts_with('-') => {
            format!("{mantissa}e+{exp:0>2}")
        }
        _ => text,
    }
}

pub fn escape(out: &mut String, text: &str) {
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_nested_values() {
        let text = r#" [{"Id":"a\"b","N":-1.5e2,"L":{"k":"é😀"},
            "T":true,"X":null,"E":[]}] "#;
        let json = Json::parse(text).unwrap();
        let first = &json.arr()[0];
        assert_eq!(first.get("Id").and_then(Json::str), Some("a\"b"));
        assert_eq!(first.get("N").and_then(Json::num), Some(-150.0));
        let label = first.get("L").and_then(|l| l.get("k"));
        assert_eq!(label.and_then(Json::str), Some("é😀"));
        assert!(first.get("T").is_some_and(Json::bool));
        assert!(first.get("E").is_some_and(|e| e.arr().is_empty()));
    }

    #[test]
    fn refuses_broken_text() {
        assert!(Json::parse("{\"a\":}").is_none());
        assert!(Json::parse("[1,2").is_none());
        assert!(Json::parse("[1] x").is_none());
    }

    #[test]
    fn escapes_for_strings() {
        let mut out = String::new();
        escape(&mut out, "a\"b\\c\nd\u{1}");
        assert_eq!(out, r#"a\"b\\c\nd\u0001"#);
    }
}
