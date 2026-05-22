use crate::parser::EtwEvent;
use serde_json;
use std::io::{self, Write};

pub fn emit_event(event: &EtwEvent) {
    if let Ok(json_str) = serde_json::to_string(event) {
        println!("{}", json_str);
        let _ = io::stdout().flush();
    }
}
