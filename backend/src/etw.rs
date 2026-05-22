use crate::parser::parse_raw_event;
use crate::stream::emit_event;
use serde_json::Value;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::thread;
use std::time::Duration;

#[cfg(windows)]
pub fn start_real_etw_session(providers: Vec<String>) {
    // In a full implementation for Windows, this would use the `windows` crate or `ferrisetw`
    // to call StartTrace, EnableTraceEx2, and ProcessTrace.
    eprintln!("[!] Real ETW subscription is a placeholder in this cross-platform codebase.");
    eprintln!("[!] Compiled for Windows, but running mock stream for now.");
}

pub fn start_mock_stream(filepath: &str, events_per_sec: u64) {
    let file = File::open(filepath).expect("Failed to open mock JSON file");
    let reader = BufReader::new(file);

    let delay = if events_per_sec > 0 {
        Duration::from_millis(1000 / events_per_sec)
    } else {
        Duration::from_millis(0)
    };

    for line in reader.lines() {
        if let Ok(content) = line {
            let content = content.trim().trim_end_matches(',');
            if content.starts_with('{') {
                if let Ok(val) = serde_json::from_str::<Value>(content) {
                    if let Some(event) = parse_raw_event(val) {
                        emit_event(&event);
                        if delay.as_millis() > 0 {
                            thread::sleep(delay);
                        }
                    }
                }
            }
        }
    }
}
