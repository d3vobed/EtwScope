import math
from collections import Counter
from typing import List, Dict, Any, Tuple
from datetime import datetime, timezone

def parse_ts(s: str) -> datetime:
    """Parse ISO timestamp."""
    try:
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is not None:
            dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
        return dt
    except:
        try:
            return datetime.fromisoformat(s[:19])
        except:
            return datetime.now()

class MetricsEngine:
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
        F = len(self.events)
        if F == 0:
            return {"F": 0, "H": 0.0, "CV_t": 0.0, "total": self.total_processed}

        # Entropy
        names = [e.get("event_name", "Unknown") for e in self.events]
        counts = Counter(names)
        probs = [c/F for c in counts.values()]
        H = -sum(p * math.log2(p) for p in probs if p > 0)
        H = max(H, 0.0)

        # Timing (CV_t)
        ts_list = []
        for e in self.events:
            ts_str = e.get("timestamp_str")
            if ts_str:
                ts_list.append(parse_ts(ts_str))
        
        ts_list.sort()
        CV_t = 0.0
        if len(ts_list) > 1:
            gaps = [(ts_list[i+1]-ts_list[i]).total_seconds()*1e6 for i in range(len(ts_list)-1)]
            mean_g = sum(gaps)/len(gaps)
            if mean_g > 0:
                std_g = (sum((g-mean_g)**2 for g in gaps)/len(gaps))**0.5
                CV_t = std_g / mean_g

        return {"F": F, "H": H, "CV_t": CV_t, "total": self.total_processed}
