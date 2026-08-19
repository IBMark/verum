//! Recall fixture: known Rust true positives that must keep firing. If an
//! FP-reduction change ever silences one of these, the recall test fails.

use std::sync::mpsc;

// A genuinely dead private function: no caller, not `_`-prefixed, not a trait
// method, not in benches/examples. Must be reported as dead code.
fn orphaned_helper(x: u32) -> u32 {
    x.wrapping_mul(7)
}

// Hot-path panic: the fn name is a hot hint (`handle`), and the unwrap is on a
// genuinely fallible operation (not a lock guard / infallible idiom). Must fire
// PanicRisk on a latency-sensitive path.
pub fn handle_packet(buf: &[u8]) -> usize {
    let text = std::str::from_utf8(buf).unwrap();
    text.len()
}

// Unbounded channel: must fire UnboundedChannel.
pub fn build_queue() -> mpsc::Receiver<u32> {
    let (tx, rx) = mpsc::channel();
    let _ = tx;
    rx
}

pub fn build_unbounded() {
    let (_tx, _rx) = tokio::sync::mpsc::unbounded_channel::<u32>();
}

// Blocking call inside an async fn: must fire BlockingInAsync.
pub async fn read_config() -> Vec<u8> {
    std::fs::read("/etc/config").unwrap_or_default()
}
