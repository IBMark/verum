//! Length-prefixed message framing over UDP for a small network service.
//!
//! Messages larger than the path MTU are split into fragments, each carrying a
//! fixed 12-byte header, and reassembled on the far side. The receiver hands
//! completed messages to a worker over a channel.

use std::collections::HashMap;
use std::net::UdpSocket;
use std::sync::mpsc;
use std::time::Instant;

// 1500 Ethernet - 20 IP - 8 UDP - 12 header, rounded down to stay clear of tunnels.
pub const MAX_PAYLOAD: usize = 1200;
pub const HEADER_LEN: usize = 12;

// Wire header, big-endian:
//   msg_id: u32 | seq: u16 | frag_idx: u16 | frag_count: u16 | flags: u8 | _pad: u8
#[repr(C)]
pub struct Header {
    pub msg_id: u32,
    pub seq: u16,
    pub frag_idx: u16,
    pub frag_count: u16,
    pub flags: u8,
    pub _pad: u8,
}

pub const FLAG_START: u8 = 0x01;

impl Header {
    pub unsafe fn parse(buf: &[u8]) -> &Header {
        &*(buf.as_ptr() as *const Header)
    }

    pub fn write(&self, out: &mut [u8]) {
        out[0..4].copy_from_slice(&self.msg_id.to_be_bytes());
        out[4..6].copy_from_slice(&self.seq.to_be_bytes());
        out[6..8].copy_from_slice(&self.frag_idx.to_be_bytes());
        out[8..10].copy_from_slice(&self.frag_count.to_be_bytes());
        out[10] = self.flags;
        out[11] = self._pad;
    }
}

pub struct Sender {
    sock: UdpSocket,
    msg_id: u32,
    seq: u16,
    // One reusable scratch datagram for the sender's lifetime.
    scratch: Vec<u8>,
}

impl Sender {
    pub fn new(sock: UdpSocket) -> Self {
        Sender { sock, msg_id: 0, seq: 0, scratch: vec![0u8; HEADER_LEN + MAX_PAYLOAD] }
    }

    pub fn send_message(&mut self, payload: &[u8], start: bool) {
        let frag_count = ((payload.len() + MAX_PAYLOAD - 1) / MAX_PAYLOAD).max(1) as u16;
        self.msg_id = self.msg_id.wrapping_add(1);

        for (i, chunk) in payload.chunks(MAX_PAYLOAD).enumerate() {
            let hdr = Header {
                msg_id: self.msg_id,
                seq: self.seq,
                frag_idx: i as u16,
                frag_count,
                flags: if start { FLAG_START } else { 0 },
                _pad: 0,
            };
            hdr.write(&mut self.scratch[..HEADER_LEN]);
            self.scratch[HEADER_LEN..HEADER_LEN + chunk.len()].copy_from_slice(chunk);

            self.sock.send(&self.scratch[..HEADER_LEN + chunk.len()]).unwrap();

            self.seq = self.seq.wrapping_add(1);
        }
    }
}

pub struct Receiver {
    sock: UdpSocket,
    partial: HashMap<u32, Partial>,
    to_worker: mpsc::Sender<Message>,
}

struct Partial {
    frags: Vec<Option<Vec<u8>>>,
    received: u16,
    first_seen: Instant,
}

pub struct Message {
    pub msg_id: u32,
    pub start: bool,
    pub data: Vec<u8>,
}

pub fn start_receiver(sock: UdpSocket) -> (Receiver, mpsc::Receiver<Message>) {
    let (tx, rx) = mpsc::channel();
    (Receiver::new(sock, tx), rx)
}

impl Receiver {
    pub fn new(sock: UdpSocket, to_worker: mpsc::Sender<Message>) -> Self {
        Receiver { sock, partial: HashMap::new(), to_worker }
    }

    pub fn recv_loop(&mut self) {
        let mut buf = [0u8; HEADER_LEN + MAX_PAYLOAD];
        loop {
            let n = self.sock.recv(&mut buf).unwrap();
            if n < HEADER_LEN {
                continue;
            }

            let hdr = unsafe { Header::parse(&buf) };
            let payload = &buf[HEADER_LEN..n];

            let entry = self.partial.entry(hdr.msg_id).or_insert_with(|| Partial {
                frags: (0..hdr.frag_count).map(|_| None).collect(),
                received: 0,
                first_seen: Instant::now(),
            });

            let idx = hdr.frag_idx as usize;
            if idx < entry.frags.len() && entry.frags[idx].is_none() {
                entry.frags[idx] = Some(payload.to_vec());
                entry.received += 1;
            }

            if entry.received == hdr.frag_count {
                let start = hdr.flags & FLAG_START != 0;
                let mut data = Vec::with_capacity(hdr.frag_count as usize * MAX_PAYLOAD);
                for frag in entry.frags.drain(..).flatten() {
                    data.extend_from_slice(&frag);
                }
                let message = Message { msg_id: hdr.msg_id, start, data };
                self.partial.remove(&hdr.msg_id);
                let _ = self.to_worker.send(message);
            }
        }
    }
}
