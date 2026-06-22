"""Live Anomaly Detection Engine — Classifies ETW events in real-time.

This module provides the core detection logic for the Live Monitor mode.
It maintains a rolling baseline profile and flags anomalous events that
indicate potential evasion techniques (Direct Syscalls, HWBP, ETW patching).

Unlike passive loggers (SilkETW, EtwExplorer), this engine actively
classifies events as they arrive, enabling real-time visibility measurement.
"""
from collections import Counter, deque
from typing import Dict, Any, List, Tuple, Optional
import time
import math


# =============================================================================
# Known Indicators of Compromise / Evasion Technique Signatures
# =============================================================================

# Events that are CRITICAL for EDR visibility — if these disappear,
# it means an evasion technique is actively suppressing telemetry
CRITICAL_VISIBILITY_EVENTS = {
    "ImageLoad", "ImageUnload",           # DLL injection detection
    "ProcessStart", "ProcessStop",         # Process hollowing detection
    "ThreadStart", "ThreadStop",           # Remote thread injection detection
    "PagePriorityChange",                  # Memory manipulation marker
    "ProcessStart/Start", "ProcessStop/Stop",
    "ThreadStart/Start", "ThreadStop/Stop",
    "ImageLoad/Start",
}

# Events that indicate INJECTION activity when they appear unexpectedly
INJECTION_INDICATORS = {
    "ThreadStart": "Remote Thread Injection (CreateRemoteThread / NtCreateThreadEx)",
    "ImageLoad":   "Reflective DLL Injection or DLL Side-Loading",
    "ProcessStart": "Process Hollowing / Process Doppelganging",
    "PagePriorityChange": "Memory Permission Change (VirtualProtectEx)",
    "ProcessStop": "Process Termination (potential cleanup after injection)",
}

# Syscalls that are commonly abused by malware
SUSPICIOUS_SYSCALLS = {
    "NtAllocateVirtualMemory", "NtWriteVirtualMemory", "NtProtectVirtualMemory",
    "NtCreateThreadEx", "NtCreateThread", "NtCreateProcess", "NtCreateProcessEx",
    "NtMapViewOfSection", "NtUnmapViewOfSection", "NtQueueApcThread",
    "NtSuspendThread", "NtResumeThread", "NtSetContextThread",
    "NtReadVirtualMemory", "NtOpenProcess",
}


class LiveDetector:
    """Real-time ETW event classifier with rolling baseline profiling.
    
    Operates in two phases:
      Phase 1 (Baseline): Collects events for `baseline_window` seconds to
                           establish normal OS event rates and distributions.
      Phase 2 (Detection): Compares incoming events against the baseline
                           profile and flags deviations as anomalies.
    """

    # Risk levels and their display colors
    RISK_NORMAL     = ("normal",     "green",   "")
    RISK_INFO       = ("info",       "cyan",    "")
    RISK_SUSPICIOUS = ("suspicious", "yellow",  "")
    RISK_CRITICAL   = ("critical",   "red",     "")

    def __init__(self, baseline_window_seconds: int = 15):
        self.baseline_window = baseline_window_seconds
        self.start_time: Optional[float] = None
        self.baseline_established = False

        # Baseline profile
        self._baseline_events: List[Dict] = []
        self._baseline_rates: Dict[str, float] = {}   # event_name -> events/sec
        self._baseline_total_rate: float = 0.0

        # Rolling detection window (last 5 seconds)
        self._detection_window = deque(maxlen=5000)
        self._detection_window_start: float = 0.0

        # Counters
        self.total_events = 0
        self.normal_count = 0
        self.suspicious_count = 0
        self.critical_count = 0

        # Per-event-type counters for live TRS
        self._live_type_counts: Counter = Counter()

        # Track unique processes seen (for cross-process injection detection)
        self._known_pids: set = set()
        self._pid_first_seen: Dict[str, float] = {}

    def classify_event(self, event: Dict[str, Any]) -> Tuple[str, str, str]:
        """Classify a single ETW event and return (risk_level, color, note).
        
        Returns:
            Tuple of (risk_level, css_color, classification_note)
        """
        now = time.time()
        if self.start_time is None:
            self.start_time = now

        self.total_events += 1
        event_name = event.get("event_name", "Unknown")
        provider = event.get("provider_name", "Unknown")
        pid = event.get("pid")

        # Track the event
        self._live_type_counts[event_name] += 1
        self._detection_window.append((now, event))

        # Phase 1: Baseline collection
        elapsed = now - self.start_time
        if not self.baseline_established:
            self._baseline_events.append(event)
            if elapsed >= self.baseline_window:
                self._establish_baseline()
            # During baseline, still flag obviously suspicious events
            return self._check_static_signatures(event_name, provider, pid, now)

        # Phase 2: Active detection
        return self._detect_anomaly(event, event_name, provider, pid, now)

    def _establish_baseline(self):
        """Compute the baseline profile from collected events."""
        self.baseline_established = True
        duration = self.baseline_window
        if duration <= 0:
            duration = 1

        # Compute per-event-type rates
        counts = Counter(e.get("event_name", "Unknown") for e in self._baseline_events)
        self._baseline_rates = {name: count / duration for name, count in counts.items()}
        self._baseline_total_rate = len(self._baseline_events) / duration

        # Track baseline PIDs
        for e in self._baseline_events:
            pid = e.get("pid")
            if pid:
                self._known_pids.add(pid)

    def _check_static_signatures(self, event_name: str, provider: str,
                                  pid: str, now: float) -> Tuple[str, str, str]:
        """Check against known signatures regardless of baseline state."""
        # Track new PIDs
        if pid and pid not in self._known_pids:
            self._known_pids.add(pid)
            self._pid_first_seen[pid] = now

        # Check for injection indicators
        if event_name in INJECTION_INDICATORS:
            # Is this a new PID we haven't seen before?
            if pid and pid in self._pid_first_seen:
                age = now - self._pid_first_seen[pid]
                if age < 2.0:  # PID appeared very recently
                    self.suspicious_count += 1
                    return ("suspicious", "yellow",
                            f"⚠ {INJECTION_INDICATORS[event_name]} — New PID {pid}")

            self.normal_count += 1
            return ("info", "cyan", f"Syscall-related: {event_name}")

        # Check for critical visibility events
        if event_name in CRITICAL_VISIBILITY_EVENTS:
            self.normal_count += 1
            return ("info", "cyan", "Visibility-critical event")

        self.normal_count += 1
        return ("normal", "green", "")

    def _detect_anomaly(self, event: Dict, event_name: str, provider: str,
                        pid: str, now: float) -> Tuple[str, str, str]:
        """Compare event against baseline profile to detect anomalies."""

        # 1. New PID never seen in baseline
        if pid and pid not in self._known_pids:
            self._known_pids.add(pid)
            self._pid_first_seen[pid] = now

            # A new process appearing after baseline is noteworthy
            if event_name in ("ProcessStart", "ProcessStart/Start"):
                self.suspicious_count += 1
                return ("suspicious", "yellow",
                        f"⚠ New process spawned post-baseline (PID {pid})")

        # 2. Injection pattern: ThreadStart targeting a different PID
        if event_name in ("ThreadStart", "ThreadStart/Start"):
            if pid and pid in self._pid_first_seen:
                age = now - self._pid_first_seen.get(pid, now)
                if age < 3.0:
                    self.critical_count += 1
                    return ("critical", "red",
                            f"🔴 Remote Thread Injection Detected — PID {pid}")

        # 3. Event-type rate anomaly (sudden spike or drop)
        baseline_rate = self._baseline_rates.get(event_name, 0)
        if baseline_rate > 0:
            # Calculate current rate for this event type in last 3 seconds
            recent_count = sum(1 for t, e in self._detection_window
                              if now - t < 3.0 and e.get("event_name") == event_name)
            current_rate = recent_count / 3.0

            # Significant spike (>5x baseline rate)
            if current_rate > baseline_rate * 5 and recent_count > 10:
                self.suspicious_count += 1
                return ("suspicious", "yellow",
                        f"⚠ Rate anomaly: {current_rate:.1f}/s vs baseline {baseline_rate:.1f}/s")

        # 4. Event type never seen in baseline
        if event_name not in self._baseline_rates and event_name != "Unknown":
            self.suspicious_count += 1
            return ("suspicious", "yellow",
                    f"⚠ New event type (not in baseline): {event_name}")

        # 5. Standard injection indicator check
        if event_name in INJECTION_INDICATORS:
            self.normal_count += 1
            return ("info", "cyan", INJECTION_INDICATORS[event_name])

        if event_name in CRITICAL_VISIBILITY_EVENTS:
            self.normal_count += 1
            return ("info", "cyan", "Visibility-critical")

        self.normal_count += 1
        return ("normal", "green", "")

    def compute_live_trs(self, baseline_profile: Optional[Dict] = None) -> Dict[str, Any]:
        """Compute a running TRS based on the current detection window vs baseline.
        
        Returns dict with trs, visibility_pct, event_rate, anomaly_rate.
        """
        now = time.time()
        elapsed = now - self.start_time if self.start_time else 1.0
        if elapsed <= 0:
            elapsed = 1.0

        event_rate = self.total_events / elapsed

        # If baseline not established yet, return neutral TRS
        if not self.baseline_established:
            return {
                "trs": 1.0,
                "visibility_pct": 100.0,
                "event_rate": event_rate,
                "anomaly_rate": 0.0,
                "phase": "BASELINE",
                "baseline_progress": min(
                    (now - self.start_time) / self.baseline_window * 100, 100
                ) if self.start_time else 0,
            }

        # Compare current event distribution to baseline
        # Recent events (last 5 seconds)
        recent_events = [(t, e) for t, e in self._detection_window if now - t < 5.0]
        if not recent_events:
            return {
                "trs": 1.0, "visibility_pct": 100.0,
                "event_rate": 0, "anomaly_rate": 0,
                "phase": "MONITORING",
            }

        recent_counts = Counter(e.get("event_name", "Unknown") for _, e in recent_events)
        recent_duration = 5.0

        # Volume ratio (are we seeing as many events as baseline?)
        current_total_rate = len(recent_events) / recent_duration
        vol_ratio = min(current_total_rate / self._baseline_total_rate, 1.0) \
            if self._baseline_total_rate > 0 else 1.0

        # Entropy ratio
        baseline_entropy = self._compute_entropy(
            Counter(e.get("event_name", "Unknown") for e in self._baseline_events)
        )
        current_entropy = self._compute_entropy(recent_counts)
        ent_ratio = min(current_entropy / baseline_entropy, 1.0) \
            if baseline_entropy > 0 else 1.0

        # Anomaly component
        anomaly_rate = (self.suspicious_count + self.critical_count) / self.total_events \
            if self.total_events > 0 else 0
        anomaly_penalty = min(anomaly_rate * 5, 0.3)  # max 30% penalty

        trs = 0.45 * vol_ratio + 0.35 * ent_ratio + 0.20 * (1.0 - anomaly_penalty)
        trs = max(0.0, min(trs, 1.0))

        return {
            "trs": round(trs, 4),
            "visibility_pct": round(trs * 100, 1),
            "event_rate": round(event_rate, 1),
            "anomaly_rate": round(anomaly_rate * 100, 2),
            "phase": "MONITORING",
            "vol_ratio": round(vol_ratio, 4),
            "ent_ratio": round(ent_ratio, 4),
        }

    @staticmethod
    def _compute_entropy(counts: Counter) -> float:
        """Compute Shannon entropy from a Counter."""
        total = sum(counts.values())
        if total == 0:
            return 0.0
        probs = [c / total for c in counts.values()]
        return -sum(p * math.log2(p) for p in probs if p > 0)

    def get_stats(self) -> Dict[str, Any]:
        """Return current detection statistics."""
        return {
            "total": self.total_events,
            "normal": self.normal_count,
            "suspicious": self.suspicious_count,
            "critical": self.critical_count,
            "baseline_established": self.baseline_established,
            "unique_pids": len(self._known_pids),
            "unique_event_types": len(self._live_type_counts),
        }
