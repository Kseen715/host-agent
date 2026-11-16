//! SNMP v2c over UDP, as much as walking a device takes: BER for a
//! GetBulkRequest and its Response (RFC 3416), one request at a time.

use super::transport::Transport;
use std::io;
use std::time::Instant;

/// snmp_exporter's.
const MAX_REPETITIONS: i64 = 25;
const RETRIES: u64 = 2;
/// snmp_exporter's snmp_packet_duration_seconds buckets: 0.1 ms
/// doubled 15 times.
pub const BUCKETS: usize = 15;

pub fn bucket_bound(index: usize) -> f64 {
    0.0001 * f64::from(1u32 << index)
}

pub enum Value {
    Number(f64),
    Bytes(Vec<u8>),
    Oid(String),
}

pub struct Client<T> {
    transport: T,
    community: Vec<u8>,
    request_id: i64,
    buf: Vec<u8>,
    pub sent: u64,
    pub retried: u64,
    /// Answers that were not a Response PDU.
    pub unexpected: u64,
    /// Each answered request's time, from its first sending: counts
    /// per bucket (not cumulative), and the sum in seconds.
    pub durations: [u64; BUCKETS + 1],
    pub duration_sum: f64,
}

impl<T: Transport> Client<T> {
    /// `address` with its port, or 161.
    pub async fn connect(address: &str, community: &str) -> io::Result<Self> {
        Ok(Client {
            transport: T::connect(address).await?,
            community: community.as_bytes().to_vec(),
            request_id: 0,
            buf: vec![0; 65536],
            sent: 0,
            retried: 0,
            unexpected: 0,
            durations: [0; BUCKETS + 1],
            duration_sum: 0.0,
        })
    }

    /// Every variable under `root`, in the device's order.
    pub async fn walk(
        &mut self,
        root: &str,
        out: &mut Vec<(String, Value)>,
    ) -> io::Result<()> {
        let prefix = format!("{root}.");
        let mut from = root.to_owned();
        loop {
            let binds = self.get_bulk(&from).await?;
            let last = from.clone();
            for (oid, value) in binds {
                let Some(value) = value.filter(|_| oid.starts_with(&prefix))
                else {
                    return Ok(());
                };
                from.clone_from(&oid);
                out.push((oid, value));
            }
            // An empty answer, or one going nowhere, ends it.
            if from == last {
                return Ok(());
            }
        }
    }

    async fn get_bulk(&mut self, oid: &str) -> io::Result<Vec<Bind>> {
        self.request_id = (self.request_id + 1) & 0x7fff_ffff;
        let request = request(&self.community, self.request_id, oid)
            .ok_or_else(|| io::Error::other(format!("bad OID {oid}")))?;
        let start = Instant::now();
        for attempt in 0..=RETRIES {
            self.retried += u64::from(attempt > 0);
            self.transport.send(&request).await?;
            self.sent += 1;
            loop {
                let length = match self.transport.recv(&mut self.buf).await {
                    Ok(length) => length,
                    Err(e) if e.kind() == io::ErrorKind::TimedOut => break,
                    Err(e) => return Err(e),
                };
                // Another request's answer, late: wait on.
                let answer = &self.buf[..length];
                self.unexpected += u64::from(!is_response(answer));
                if let Some(answer) = response(answer, self.request_id) {
                    self.observe(start.elapsed().as_secs_f64());
                    return answer;
                }
            }
        }
        Err(io::Error::new(io::ErrorKind::TimedOut, "no answer"))
    }

    fn observe(&mut self, seconds: f64) {
        let bucket = (0..BUCKETS).find(|&i| seconds <= bucket_bound(i));
        self.durations[bucket.unwrap_or(BUCKETS)] += 1;
        self.duration_sum += seconds;
    }
}

/// A variable and its value; None past the end of the device's MIB.
type Bind = (String, Option<Value>);

fn request(community: &[u8], id: i64, oid: &str) -> Option<Vec<u8>> {
    let bind = tlv(0x30, &[encode_oid(oid)?, vec![0x05, 0x00]].concat());
    let fields = [
        integer(id),
        integer(0),
        integer(MAX_REPETITIONS),
        tlv(0x30, &bind),
    ];
    let pdu = tlv(0xA5, &fields.concat());
    Some(tlv(0x30, &[integer(1), tlv(0x04, community), pdu].concat()))
}

pub(super) fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let length = content.len().to_be_bytes();
    let skip = length.iter().take_while(|&&b| b == 0).count();
    if content.len() < 0x80 {
        out.push(content.len() as u8);
    } else {
        out.push(0x80 | (length.len() - skip) as u8);
        out.extend_from_slice(&length[skip..]);
    }
    out.extend_from_slice(content);
    out
}

/// The fewest two's complement bytes that keep the sign.
fn integer(value: i64) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let redundant = |i: usize| {
        (bytes[i] == 0 && bytes[i + 1] < 0x80)
            || (bytes[i] == 0xff && bytes[i + 1] >= 0x80)
    };
    let start = (0..7).take_while(|&i| redundant(i)).count();
    tlv(0x02, &bytes[start..])
}

fn encode_oid(text: &str) -> Option<Vec<u8>> {
    let arcs: Vec<u32> = text
        .split('.')
        .map(|a| a.parse().ok())
        .collect::<Option<_>>()?;
    let [first, second, rest @ ..] = &arcs[..] else {
        return None;
    };
    let mut out = Vec::new();
    for arc in std::iter::once(first * 40 + second).chain(rest.iter().copied())
    {
        let mut groups = vec![(arc & 0x7f) as u8];
        let mut arc = arc >> 7;
        while arc > 0 {
            groups.push(0x80 | (arc & 0x7f) as u8);
            arc >>= 7;
        }
        out.extend(groups.iter().rev());
    }
    Some(tlv(0x06, &out))
}

/// The first TLV in `buf`: its tag, its content, and what follows it.
fn read(buf: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = buf.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (length, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let count = usize::from(first & 0x7f);
        if count > 4 || rest.len() < count {
            return None;
        }
        let length = rest[..count]
            .iter()
            .fold(0, |length, &b| length << 8 | usize::from(b));
        (length, &rest[count..])
    };
    (rest.len() >= length).then(|| (tag, &rest[..length], &rest[length..]))
}

/// The variables of the Response to request `id`; None for anything
/// else.
/// Whether `buf` is an SNMP message carrying a Response PDU.
fn is_response(buf: &[u8]) -> bool {
    let pdu = || {
        let (0x30, message, _) = read(buf)? else {
            return None;
        };
        let (_, _version, rest) = read(message)?;
        let (_, _community, rest) = read(rest)?;
        read(rest).map(|(tag, _, _)| tag)
    };
    pdu() == Some(0xA2)
}

fn response(buf: &[u8], id: i64) -> Option<io::Result<Vec<Bind>>> {
    let (0x30, message, _) = read(buf)? else {
        return None;
    };
    let (_, _version, rest) = read(message)?;
    let (_, _community, rest) = read(rest)?;
    let (0xA2, pdu, _) = read(rest)? else {
        return None;
    };
    let (_, request_id, rest) = read(pdu)?;
    if signed(request_id) != id {
        return None;
    }
    let (_, status, rest) = read(rest)?;
    if signed(status) != 0 {
        let error = format!("error status {}", signed(status));
        return Some(Err(io::Error::other(error)));
    }
    let (_, _index, rest) = read(rest)?;
    let (_, mut binds, _) = read(rest)?;
    let mut out = Vec::new();
    while !binds.is_empty() {
        let (_, bind, rest) = read(binds)?;
        binds = rest;
        let (_, name, value) = read(bind)?;
        let (tag, content, _) = read(value)?;
        out.push((decode_oid(name), value_of(tag, content)));
    }
    Some(Ok(out))
}

fn value_of(tag: u8, content: &[u8]) -> Option<Value> {
    let unsigned = || content.iter().fold(0u64, |n, &b| n << 8 | u64::from(b));
    match tag {
        0x02 => Some(Value::Number(signed(content) as f64)),
        // Counter32, Gauge32, TimeTicks, Counter64.
        0x41..=0x43 | 0x46 => Some(Value::Number(unsigned() as f64)),
        // Net-SNMP's floats (laLoadFloat): an Opaque wrapping one.
        0x44 if content.len() == 7 && content[..3] == [0x9f, 0x78, 4] => {
            let bytes = [content[3], content[4], content[5], content[6]];
            Some(Value::Number(f64::from(f32::from_be_bytes(bytes))))
        }
        0x04 | 0x40 | 0x44 => Some(Value::Bytes(content.to_vec())),
        0x06 => Some(Value::Oid(decode_oid(content))),
        // NULL, noSuchObject, noSuchInstance, endOfMibView.
        _ => None,
    }
}

fn signed(content: &[u8]) -> i64 {
    let negative = content.first().is_some_and(|&b| b >= 0x80);
    let start = if negative { -1 } else { 0 };
    content.iter().fold(start, |n, &b| n << 8 | i64::from(b))
}

fn decode_oid(content: &[u8]) -> String {
    let mut arcs = Vec::new();
    let mut arc: u64 = 0;
    for &byte in content {
        arc = arc << 7 | u64::from(byte & 0x7f);
        if byte < 0x80 {
            arcs.push(arc);
            arc = 0;
        }
    }
    let Some(&first) = arcs.first() else {
        return String::new();
    };
    let (a, b) = if first < 80 {
        (first / 40, first % 40)
    } else {
        (2, first - 80)
    };
    let rest = arcs[1..].iter().map(|arc| format!(".{arc}"));
    format!("{a}.{b}{}", rest.collect::<String>())
}

/// A v2c agent on loopback answering each GetBulkRequest from `table`
/// (OIDs in the MIB's order, values whole TLVs), as a device's would:
/// it leaves the first `lost` requests unanswered and sends a Trap
/// before each answer.
#[cfg(test)]
pub(super) fn agent(
    table: Vec<(&'static str, Vec<u8>)>,
    lost: usize,
) -> std::net::SocketAddr {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = socket.local_addr().unwrap();
    let mut buf = vec![0; 65536];
    std::thread::spawn(move || {
        for _ in 0..lost {
            socket.recv_from(&mut buf).unwrap();
        }
        loop {
            let (length, from) = socket.recv_from(&mut buf).unwrap();
            let (id, oid, max) = bulk(&buf[..length]).unwrap();
            let trap = [integer(id), integer(0), integer(0), tlv(0x30, &[])];
            let trap = tlv(0xA7, &trap.concat());
            for pdu in [trap, answer(&table, id, &oid, max)] {
                let message = [integer(1), tlv(0x04, b"public"), pdu];
                let message = tlv(0x30, &message.concat());
                socket.send_to(&message, from).unwrap();
            }
        }
    });
    address
}

/// A GetBulkRequest's id, first variable and max-repetitions.
#[cfg(test)]
fn bulk(buf: &[u8]) -> Option<(i64, String, i64)> {
    let (_, message, _) = read(buf)?;
    let (_, _version, rest) = read(message)?;
    let (_, _community, rest) = read(rest)?;
    let (0xA5, pdu, _) = read(rest)? else {
        return None;
    };
    let (_, id, rest) = read(pdu)?;
    let (_, _non_repeaters, rest) = read(rest)?;
    let (_, max, rest) = read(rest)?;
    let (_, binds, _) = read(rest)?;
    let (_, bind, _) = read(binds)?;
    let (_, name, _) = read(bind)?;
    Some((signed(id), decode_oid(name), signed(max)))
}

/// The Response PDU: up to `max` variables of `table` after `oid`, or
/// endOfMibView past its end.
#[cfg(test)]
fn answer(table: &[(&str, Vec<u8>)], id: i64, oid: &str, max: i64) -> Vec<u8> {
    let arcs = |oid: &str| -> Vec<u32> {
        oid.split('.').map(|a| a.parse().unwrap()).collect()
    };
    let bind = |oid: &str, value: &[u8]| {
        tlv(0x30, &[encode_oid(oid).unwrap(), value.to_vec()].concat())
    };
    let after = table.iter().filter(|(o, _)| arcs(o) > arcs(oid));
    let mut binds: Vec<Vec<u8>> = after
        .take(max as usize)
        .map(|(o, value)| bind(o, value))
        .collect();
    if binds.is_empty() {
        binds.push(bind(oid, &tlv(0x82, &[])));
    }
    let fields = [
        integer(id),
        integer(0),
        integer(0),
        tlv(0x30, &binds.concat()),
    ];
    tlv(0xA2, &fields.concat())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let oid = "1.3.6.1.2.1.31.1.1.1.18.200";
        let encoded = encode_oid(oid).unwrap();
        let (_, content, _) = read(&encoded).unwrap();
        assert_eq!(decode_oid(content), oid);
        for n in [0, 127, 128, -1, -129, 0x7fff_ffff] {
            let encoded = integer(n);
            let (_, content, _) = read(&encoded).unwrap();
            assert_eq!(signed(content), n);
        }
        let long = tlv(0x04, &[7; 300]);
        assert_eq!(&long[..4], [0x04, 0x82, 0x01, 0x2c]);
        assert_eq!(read(&long).unwrap().1.len(), 300);
    }

    #[test]
    fn reads_a_response() {
        let bind = |oid: &str, value: Vec<u8>| {
            tlv(0x30, &[encode_oid(oid).unwrap(), value].concat())
        };
        let binds = [
            bind("1.3.6.1.2.1.1.3.0", tlv(0x43, &[0x01, 0x00])),
            bind("1.3.6.1.2.1.1.5.0", tlv(0x04, b"keenetic")),
            bind("1.3.6.1.2.1.2.1.0", vec![0x82, 0x00]),
        ]
        .concat();
        let pdu = [integer(7), integer(0), integer(0), tlv(0x30, &binds)];
        let message = [integer(1), tlv(0x04, b"c"), tlv(0xA2, &pdu.concat())];
        let message = tlv(0x30, &message.concat());
        assert!(response(&message, 8).is_none());
        let binds = response(&message, 7).unwrap().unwrap();
        assert!(matches!(binds[0].1, Some(Value::Number(256.0))));
        assert!(
            matches!(&binds[1].1, Some(Value::Bytes(b)) if b == b"keenetic")
        );
        assert!(binds[2].1.is_none());
    }
}
