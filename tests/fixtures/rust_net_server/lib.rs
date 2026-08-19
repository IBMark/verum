//! Example Rust network service used to exercise the analyzer across
//! transports. Each module carries both a real defect (which the analyzer
//! should flag) and a safe equivalent (which it should not), so the fixture
//! doubles as a false-positive regression guard.

pub mod control;
pub mod quic;
pub mod tcp;
pub mod transport;
