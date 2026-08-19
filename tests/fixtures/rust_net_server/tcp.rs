//! Length-prefixed framing over a TCP stream.

use std::io::Read;
use std::net::TcpStream;

/// Reads a frame whose length prefix is trusted directly from the wire.
/// A hostile peer sends a huge length and the server allocates it before
/// reading a byte.
pub fn read_frame_unbounded(stream: &mut TcpStream) -> Vec<u8> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).unwrap();
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).unwrap();
    buf
}

/// The same framing, but the length is bounded before it's used as a size.
pub const MAX_FRAME: usize = 1 << 20;

pub fn read_frame_bounded(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let frame_len = u32::from_be_bytes(len_buf) as usize;
    if frame_len > MAX_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "frame exceeds MAX_FRAME",
        ));
    }
    let mut buf = vec![0u8; frame_len];
    stream.read_exact(&mut buf)?;
    Ok(buf)
}
