//! Async control plane for the service: session setup, telemetry, rate feedback.
//! The data plane runs on its own thread (see transport.rs); this only handles
//! the slow path.

use std::sync::Mutex;
use std::time::Duration;

pub struct RateController {
    target_kbps: Mutex<u32>,
}

impl RateController {
    pub fn new() -> Self {
        RateController { target_kbps: Mutex::new(4000) }
    }

    // Back off on rising delay (a queue building on the path) before loss forces
    // it. `on_` prefix marks this a latency-sensitive path.
    pub fn on_delay_sample(&self, delay_gradient_ms: f32) {
        let mut target = self.target_kbps.lock().unwrap();
        if delay_gradient_ms > 1.0 {
            *target = (*target as f32 * 0.85) as u32;
        } else {
            *target = (*target + 200).min(8000);
        }
    }
}

pub async fn supervise(ctrl: &RateController) {
    loop {
        // Blocking file I/O and a blocking sleep inside an async fn both park the
        // executor thread and stall every other task on it.
        std::fs::write("/tmp/service_heartbeat", b"alive").unwrap();
        std::thread::sleep(Duration::from_millis(500));
        ctrl.on_delay_sample(0.5);
    }
}
