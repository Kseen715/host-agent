//! One journal file, read as journald writes it (systemd's
//! JOURNAL_FILE_FORMAT.md): the header, the chain of entry arrays, the
//! entries and their data objects, in the regular or compact layout.
//! Read with pread, not mapped: a few entries a second.

use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt;

const SIGNATURE: &[u8; 8] = b"LPKSHHRH";
const XZ: u32 = 1;
const LZ4: u32 = 2;
const KEYED_HASH: u32 = 4;
const ZSTD: u32 = 8;
const COMPACT: u32 = 16;
/// Incompatible flags this reader knows.
const KNOWN: u32 = XZ | LZ4 | KEYED_HASH | ZSTD | COMPACT;
const STATE_ARCHIVED: u8 = 2;
const OBJECT_DATA: u8 = 1;
const OBJECT_ENTRY: u8 = 3;
const OBJECT_ENTRY_ARRAY: u8 = 6;
/// A data object larger than this is not read.
const MAX_OBJECT: u64 = 16 << 20;
/// Entry offsets read from an array at once.
const ITEMS_AT_ONCE: u64 = 64;

pub struct Header {
    pub archived: bool,
    pub seqnum_id: [u8; 16],
    pub tail_seqnum: u64,
    pub tail_realtime: u64,
    entry_array: u64,
}

/// An entry's place in the journal and its fields as `NAME=value`.
pub struct Entry {
    pub seqnum_id: [u8; 16],
    pub seqnum: u64,
    pub realtime: u64,
    pub monotonic: u64,
    pub boot_id: [u8; 16],
    pub xor_hash: u64,
    pub fields: Vec<Vec<u8>>,
}

pub struct JournalFile {
    file: File,
    compact: bool,
    seqnum_id: [u8; 16],
    /// The entry array being read, and the index in it of the next
    /// entry; 0: the first array, not yet found.
    array: u64,
    index: u64,
}

impl JournalFile {
    pub fn open(file: File) -> io::Result<(JournalFile, Header)> {
        let flags = u32_at(&read_at(&file, 12, 4)?);
        if read_at(&file, 0, 8)? != SIGNATURE || flags & !KNOWN != 0 {
            return Err(io::Error::other("not a journal file this reads"));
        }
        let mut journal = JournalFile {
            file,
            compact: flags & COMPACT != 0,
            seqnum_id: [0; 16],
            array: 0,
            index: 0,
        };
        let header = journal.header()?;
        journal.seqnum_id = header.seqnum_id;
        Ok((journal, header))
    }

    pub fn header(&self) -> io::Result<Header> {
        let bytes = read_at(&self.file, 0, 208)?;
        Ok(Header {
            archived: bytes[16] == STATE_ARCHIVED,
            seqnum_id: bytes[72..88].try_into().expect("16 bytes"),
            tail_seqnum: u64_at(&bytes[160..]),
            tail_realtime: u64_at(&bytes[192..]),
            entry_array: u64_at(&bytes[176..]),
        })
    }

    /// The offsets of the entries after those already taken, up to
    /// ITEMS_AT_ONCE; they are taken once `advance` is called.
    pub fn next_entries(&mut self) -> io::Result<Vec<u64>> {
        if self.array == 0 {
            self.array = self.header()?.entry_array;
            if self.array == 0 {
                return Ok(Vec::new());
            }
        }
        let size = self.object(self.array, OBJECT_ENTRY_ARRAY)?;
        let item = if self.compact { 4 } else { 8 };
        let count = (size - 24) / item;
        if self.index == count {
            let next = u64_at(&read_at(&self.file, self.array + 16, 8)?);
            if next == 0 {
                return Ok(Vec::new());
            }
            (self.array, self.index) = (next, 0);
            return self.next_entries();
        }
        let take = ITEMS_AT_ONCE.min(count - self.index);
        let at = self.array + 24 + self.index * item;
        let bytes = read_at(&self.file, at, (take * item) as usize)?;
        let offsets = bytes.chunks(item as usize).map(|b| self.offset(b));
        // Slots past the last entry written are zero.
        Ok(offsets.take_while(|&offset| offset != 0).collect())
    }

    pub fn advance(&mut self, taken: usize) {
        self.index += taken as u64;
    }

    /// The seqnum_id, seqnum and realtime of the entry at `offset`.
    pub fn place(&self, offset: u64) -> io::Result<([u8; 16], u64, u64)> {
        self.object(offset, OBJECT_ENTRY)?;
        let bytes = read_at(&self.file, offset + 16, 16)?;
        Ok((self.seqnum_id, u64_at(&bytes), u64_at(&bytes[8..])))
    }

    /// The entry at `offset`, with each field journald compressed
    /// decompressed.
    pub fn entry(&self, offset: u64) -> io::Result<Entry> {
        let size = self.object(offset, OBJECT_ENTRY)?;
        let bytes = read_at(&self.file, offset, size as usize)?;
        let item = if self.compact { 4 } else { 16 };
        let fields = bytes[64..].chunks_exact(item).map(|b| self.offset(b));
        Ok(Entry {
            seqnum_id: self.seqnum_id,
            seqnum: u64_at(&bytes[16..]),
            realtime: u64_at(&bytes[24..]),
            monotonic: u64_at(&bytes[32..]),
            boot_id: bytes[40..56].try_into().expect("16 bytes"),
            xor_hash: u64_at(&bytes[56..]),
            fields: fields.map(|o| self.data(o)).collect::<io::Result<_>>()?,
        })
    }

    fn data(&self, offset: u64) -> io::Result<Vec<u8>> {
        let size = self.object(offset, OBJECT_DATA)?;
        let bytes = read_at(&self.file, offset, size as usize)?;
        let payload = &bytes[if self.compact { 72 } else { 64 }..];
        match bytes[1] {
            0 => Ok(payload.to_vec()),
            4 => zstd(payload),
            2 => lz4(payload),
            _ => Err(io::Error::other("an xz field")),
        }
    }

    /// The size of the object at `offset`, which must be of `kind`.
    fn object(&self, offset: u64, kind: u8) -> io::Result<u64> {
        let head = read_at(&self.file, offset, 16)?;
        let size = u64_at(&head[8..]);
        if head[0] != kind || !(16..=MAX_OBJECT).contains(&size) {
            return Err(io::Error::other(format!("no object at {offset}")));
        }
        Ok(size)
    }

    fn offset(&self, bytes: &[u8]) -> u64 {
        if self.compact {
            u64::from(u32_at(bytes))
        } else {
            u64_at(bytes)
        }
    }
}

fn read_at(file: &File, offset: u64, length: usize) -> io::Result<Vec<u8>> {
    let mut bytes = vec![0; length];
    file.read_exact_at(&mut bytes, offset)?;
    Ok(bytes)
}

fn u32_at(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes[..4].try_into().expect("4 bytes"))
}

fn u64_at(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes[..8].try_into().expect("8 bytes"))
}

fn zstd(payload: &[u8]) -> io::Result<Vec<u8>> {
    use std::io::Read;
    let mut source = payload;
    let mut decoder = ruzstd::decoding::StreamingDecoder::new(&mut source)
        .map_err(io::Error::other)?;
    let mut out = Vec::new();
    decoder.read_to_end(&mut out)?;
    Ok(out)
}

/// journald's LZ4: the size, little-endian in 8 bytes, then the block.
fn lz4(payload: &[u8]) -> io::Result<Vec<u8>> {
    let size = payload.get(..8).map(u64_at).unwrap_or(0) as usize;
    if size as u64 > MAX_OBJECT {
        return Err(io::Error::other("an LZ4 field too large"));
    }
    let mut out = vec![0; size];
    let input = payload.get(8..).unwrap_or_default();
    let length = lz4_flex::block::decompress_into(input, &mut out)
        .map_err(io::Error::other)?;
    out.truncate(length);
    Ok(out)
}
