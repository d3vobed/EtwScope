import json
import math
from collections import Counter
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple


def parse_ts(s: str) -> datetime:
    """Parse ISO timestamp from SilkETW JSON."""
    try:
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is not None:
            dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
        return dt
    except Exception:
        try:
            return datetime.fromisoformat(s[:19])
        except Exception:
            return datetime.now()


def load_events_from_file(filepath: str, pid_filter: Optional[str] = None,
                          provider_filter: Optional[str] = None) -> List[Dict[str, Any]]:
    """Load and parse ETW JSON events from a SilkETW log file.
    
    Supports both array-format and newline-delimited JSON.
    Returns a list of normalised event dicts.
    """
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    raw_events = []

    # Try parsing as a JSON array first
    try:
        parsed = json.loads(content)
        if isinstance(parsed, list):
            raw_events = parsed
        elif isinstance(parsed, dict):
            raw_events = [parsed]
    except json.JSONDecodeError:
        # Fallback: newline-delimited JSON
        for line in content.splitlines():
            line = line.strip().rstrip(',')
            if line.startswith('{'):
                try:
                    raw_events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    events = []
    for raw in raw_events:
        event = _normalise_event(raw)
        if event is None:
            continue

        # Apply filters
        if pid_filter and event.get("pid") != pid_filter:
            continue
        if provider_filter and event.get("provider_name") != provider_filter:
            continue

        events.append(event)

    return events


def _normalise_event(raw: Dict) -> Optional[Dict[str, Any]]:
    """Normalise a raw SilkETW JSON object into a standard event dict."""
    provider = raw.get("ProviderName", "Unknown")

    # Event name extraction
    event_name = "Unknown"
    pid = None
    tid = None

    xml = raw.get("XmlEventData")
    if xml and isinstance(xml, dict):
        event_name = xml.get("EventName", event_name)
        pid_val = xml.get("PID")
        if pid_val is not None:
            pid = str(pid_val)
        tid_val = xml.get("TID")
        if tid_val is not None:
            tid = str(tid_val)

    if event_name == "Unknown":
        event_name = raw.get("EventName", event_name)

    if pid is None:
        pid_val = raw.get("ProcessID")
        if pid_val is not None:
            pid = str(pid_val)

    if tid is None:
        tid_val = raw.get("ThreadID")
        if tid_val is not None:
            tid = str(tid_val)

    # Opcode fallback for event name
    if event_name == "Unknown":
        op = raw.get("Opcode")
        if op is not None and str(op) not in ("0", "None", ""):
            event_name = f"Opcode_{op}"

    ts_str = None
    for key in ("TimeStamp", "Timestamp", "timestamp"):
        if key in raw and raw[key]:
            ts_str = str(raw[key])
            break

    return {
        "provider_name": provider,
        "event_name": event_name,
        "pid": pid,
        "tid": tid,
        "timestamp_str": ts_str,
        "raw": raw
    }


class MetricsEngine:
    """Computes F, H, CV_t over a sliding window (for live streaming)."""

    def __init__(self, window_size: int = 1000):
        self.window_size = window_size
        self.events = []
        self.total_processed = 0

    def ingest(self, event: Dict[str, Any]):
        self.events.append(event)
        self.total_processed += 1
        if len(self.events) > self.window_size:
            self.events.pop(0)

    def compute(self) -> Dict[str, Any]:
        """Compute F, H, and CV_t over the current window."""
        return compute_metrics_from_events(self.events, self.total_processed)


def compute_metrics_from_events(events: List[Dict], total_override: Optional[int] = None) -> Dict[str, Any]:
    """Compute Shannon Entropy (H), Volume (F), and Timing Variance (CV_t).
    
    This is the core mathematical engine used by both live and batch modes.
    """
    F = len(events)
    total = total_override if total_override is not None else F

    if F == 0:
        return {"F": 0, "H": 0.0, "CV_t": 0.0, "total": total,
                "event_types": {}, "provider_counts": {}}

    # Shannon Entropy
    names = [e.get("event_name", "Unknown") for e in events]
    counts = Counter(names)
    probs = [c / F for c in counts.values()]
    H = -sum(p * math.log2(p) for p in probs if p > 0)
    H = max(H, 0.0)

    # Provider counts
    providers = [e.get("provider_name", "Unknown") for e in events]
    provider_counts = dict(Counter(providers))

    # Timing variance (CV_t)
    ts_list = []
    for e in events:
        ts_str = e.get("timestamp_str")
        if ts_str:
            ts_list.append(parse_ts(ts_str))

    ts_list.sort()
    CV_t = 0.0
    if len(ts_list) > 1:
        gaps = [(ts_list[i + 1] - ts_list[i]).total_seconds() * 1e6
                for i in range(len(ts_list) - 1)]
        mean_g = sum(gaps) / len(gaps)
        if mean_g > 0:
            std_g = (sum((g - mean_g) ** 2 for g in gaps) / len(gaps)) ** 0.5
            CV_t = std_g / mean_g

    return {
        "F": F,
        "H": round(H, 6),
        "CV_t": round(CV_t, 6),
        "total": total,
        "event_types": dict(counts),
        "provider_counts": provider_counts
    }
