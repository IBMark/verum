//! QUIC-style async stream handling.

use std::sync::Mutex;
use tokio::sync::Mutex as AsyncMutex;

pub struct Connection {
    counters: Mutex<u64>,
    shared: AsyncMutex<u64>,
}

impl Connection {
    pub fn new() -> Self {
        Connection { counters: Mutex::new(0), shared: AsyncMutex::new(0) }
    }

    /// Holds a std Mutex guard across an await point: the task can be moved to
    /// another executor thread while holding the lock.
    pub async fn handle_stream_bad(&self) {
        let guard = self.counters.lock().unwrap();
        recv_datagram().await;
        let _ = *guard;
    }

    /// A tokio async mutex is meant to be held across await, so this is fine.
    pub async fn handle_stream_ok(&self) {
        let guard = self.shared.lock().await;
        recv_datagram().await;
        let _ = *guard;
    }
}

async fn recv_datagram() {}
