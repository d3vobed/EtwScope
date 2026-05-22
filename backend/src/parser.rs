use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EtwEvent {
    pub provider_name: String,
    pub event_name: String,
    pub pid: Option<String>,
    pub tid: Option<String>,
    pub opcode: Option<String>,
    pub timestamp_str: Option<String>,
    #[serde(flatten)]
    pub raw: Value,
}

pub fn parse_raw_event(val: Value) -> Option<EtwEvent> {
    let provider_name = val.get("ProviderName")
        .and_then(|v| v.as_str())
        .unwrap_or("Unknown")
        .to_string();

    let mut event_name = "Unknown".to_string();
    let mut pid = None;
    let mut tid = None;

    if let Some(xml) = val.get("XmlEventData") {
        if let Some(name) = xml.get("EventName").and_then(|v| v.as_str()) {
            event_name = name.to_string();
        }
        if let Some(p) = xml.get("PID") {
            pid = Some(if p.is_number() { p.to_string() } else { p.as_str().unwrap_or("").to_string() });
        }
        if let Some(t) = xml.get("TID") {
            tid = Some(if t.is_number() { t.to_string() } else { t.as_str().unwrap_or("").to_string() });
        }
    }

    if event_name == "Unknown" {
        if let Some(name) = val.get("EventName").and_then(|v| v.as_str()) {
            event_name = name.to_string();
        }
    }

    if pid.is_none() {
        if let Some(p) = val.get("ProcessID") {
            pid = Some(if p.is_number() { p.to_string() } else { p.as_str().unwrap_or("").to_string() });
        }
    }
    
    if tid.is_none() {
        if let Some(t) = val.get("ThreadID") {
            tid = Some(if t.is_number() { t.to_string() } else { t.as_str().unwrap_or("").to_string() });
        }
    }

    let opcode = val.get("Opcode").map(|op| {
        if op.is_number() { op.to_string() } else { op.as_str().unwrap_or("").to_string() }
    });

    let timestamp_str = val.get("TimeStamp")
        .or_else(|| val.get("Timestamp"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    Some(EtwEvent {
        provider_name,
        event_name,
        pid,
        tid,
        opcode,
        timestamp_str,
        raw: val,
    })
}
