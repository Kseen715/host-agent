//! Text encodings of log files, as Alloy's tailer decodes them: a
//! byte order mark wins over the configured encoding, lines end at the
//! encoded newline, and bytes that are not text become U+FFFD. UTF-8,
//! UTF-16 and Latin-1 are here; feature `encodings` adds the WHATWG
//! encodings by their labels.

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Charset {
    Utf8,
    Utf16Le,
    Utf16Be,
    Latin1,
    #[cfg(feature = "encodings")]
    Other(&'static encoding_rs::Encoding),
}

/// IANA's names and aliases of ISO-8859-1.
const LATIN1: [&str; 8] = [
    "iso-8859-1",
    "iso_8859-1",
    "iso_8859-1:1987",
    "latin1",
    "l1",
    "iso-ir-100",
    "ibm819",
    "cp819",
];

impl Charset {
    /// The encoding `name` names, if this build has it.
    pub fn named(name: &str) -> Option<Charset> {
        let name = name.trim().to_ascii_lowercase();
        let found = match name.as_str() {
            "utf-8" | "utf8" | "csutf8" => Charset::Utf8,
            "utf-16le" => Charset::Utf16Le,
            // IANA's UTF-16 without a BOM is big-endian.
            "utf-16" | "utf-16be" => Charset::Utf16Be,
            _ if LATIN1.contains(&name.as_str()) => Charset::Latin1,
            #[cfg(feature = "encodings")]
            _ => {
                let found = encoding_rs::Encoding::for_label(name.as_bytes())?;
                match found {
                    f if f == encoding_rs::UTF_8 => Charset::Utf8,
                    f if f == encoding_rs::UTF_16LE => Charset::Utf16Le,
                    f if f == encoding_rs::UTF_16BE => Charset::Utf16Be,
                    f => Charset::Other(f),
                }
            }
            #[cfg(not(feature = "encodings"))]
            _ => return None,
        };
        Some(found)
    }

    /// `\n` in this encoding.
    pub fn newline(self) -> &'static [u8] {
        match self {
            Charset::Utf16Le => b"\n\0",
            Charset::Utf16Be => b"\0\n",
            _ => b"\n",
        }
    }

    /// `\r` in this encoding.
    pub fn carriage_return(self) -> &'static [u8] {
        match self {
            Charset::Utf16Le => b"\r\0",
            Charset::Utf16Be => b"\0\r",
            _ => b"\r",
        }
    }

    pub fn decode(self, bytes: &[u8]) -> String {
        match self {
            Charset::Utf8 => String::from_utf8_lossy(bytes).into_owned(),
            Charset::Latin1 => bytes.iter().map(|&b| char::from(b)).collect(),
            Charset::Utf16Le | Charset::Utf16Be => {
                let unit = |pair: &[u8]| match self {
                    Charset::Utf16Le => u16::from_le_bytes([pair[0], pair[1]]),
                    _ => u16::from_be_bytes([pair[0], pair[1]]),
                };
                let units = bytes.chunks_exact(2).map(unit);
                let mut text: String = char::decode_utf16(units)
                    .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
                    .collect();
                if bytes.len() % 2 == 1 {
                    text.push(char::REPLACEMENT_CHARACTER);
                }
                text
            }
            #[cfg(feature = "encodings")]
            Charset::Other(encoding) => {
                let (text, _) = encoding.decode_without_bom_handling(bytes);
                text.into_owned()
            }
        }
    }
}

/// A byte order mark at the start of a file: the bytes to skip, and
/// the encoding it names. UTF-32's are skipped and name none, as in
/// Alloy.
pub fn bom(head: &[u8]) -> (u64, Option<Charset>) {
    if head.starts_with(&[0xEF, 0xBB, 0xBF]) {
        (3, Some(Charset::Utf8))
    } else if head.starts_with(&[0xFE, 0xFF]) {
        (2, Some(Charset::Utf16Be))
    } else if head.starts_with(&[0xFF, 0xFE]) {
        // UTF-32LE's mark starts so too: Alloy tests UTF-16LE's first.
        (2, Some(Charset::Utf16Le))
    } else if head.starts_with(&[0, 0, 0xFE, 0xFF]) {
        (4, None)
    } else {
        (0, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_as_alloy() {
        let utf16 = Charset::named("UTF-16LE").unwrap();
        assert_eq!(utf16.decode(b"h\0i\0"), "hi");
        assert_eq!(utf16.newline(), b"\n\0");
        assert_eq!(Charset::named("latin1").unwrap().decode(&[0xE9]), "é");
        assert_eq!(bom(&[0xFF, 0xFE, b'a', 0]), (2, Some(Charset::Utf16Le)));
        assert_eq!(bom(&[0xEF, 0xBB, 0xBF, b'a']), (3, Some(Charset::Utf8)));
        assert_eq!(bom(b"abcd"), (0, None));
        assert_eq!(
            Charset::named("windows-1251").is_some(),
            cfg!(feature = "encodings")
        );
    }
}
