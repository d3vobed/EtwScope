"""Diff Engine — Compares baseline vs mutated ETW telemetry.

Performs:
1. Event-type diff (missing/added event types)
2. Provider-level diff (missing providers)  
3. Layer-specific evasion categorisation (Direct Syscall / HWBP / General Loss)
4. Per-provider metric breakdown
"""
from collections import Counter
from typing import Dict, Any, List, Set
from .metrics import compute_metrics_from_events


def diff_telemetry(base_events: List[Dict], mut_events: List[Dict]) -> Dict[str, Any]:
    """Run a full telemetry comparison between baseline and mutated event sets.
    
    Returns a structured report containing:
      - missing_event_types: events in baseline but not in mutated
      - added_event_types: events in mutated but not in baseline
      - missing_providers: providers lost entirely
      - evasion_categories: classified by bypass layer
      - per_provider_metrics: breakdown by ETW provider
    """
    # Unique event types
    base_types: Set[str] = {e.get("event_name", "Unknown") for e in base_events}
    mut_types: Set[str] = {e.get("event_name", "Unknown") for e in mut_events}

    missing_types = sorted(base_types - mut_types)
    added_types = sorted(mut_types - base_types)

    # Unique providers
    base_providers: Set[str] = {e.get("provider_name", "Unknown") for e in base_events}
    mut_providers: Set[str] = {e.get("provider_name", "Unknown") for e in mut_events}
    missing_providers = sorted(base_providers - mut_providers)

    provider_reduction_pct = 0.0
    if base_providers:
        provider_reduction_pct = round(
            len(base_providers - mut_providers) / len(base_providers) * 100, 2)

    # Layer-specific evasion categorisation
    evasion_categories = classify_evasion_layers(missing_types)

    # Per-provider metrics
    per_provider = {}
    all_providers = base_providers | mut_providers
    for prov in sorted(all_providers):
        base_prov_events = [e for e in base_events if e.get("provider_name") == prov]
        mut_prov_events = [e for e in mut_events if e.get("provider_name") == prov]

        base_m = compute_metrics_from_events(base_prov_events)
        mut_m = compute_metrics_from_events(mut_prov_events)

        per_provider[prov] = {
            "baseline": {"F": base_m["F"], "H": base_m["H"], "CV_t": base_m["CV_t"]},
            "mutated": {"F": mut_m["F"], "H": mut_m["H"], "CV_t": mut_m["CV_t"]},
            "event_delta": mut_m["F"] - base_m["F"],
        }

    # Granular Event Grid
    base_counts = Counter(e.get("event_name", "Unknown") for e in base_events)
    mut_counts = Counter(e.get("event_name", "Unknown") for e in mut_events)
    
    event_diff = []
    all_events = set(base_counts.keys()) | set(mut_counts.keys())
    
    api_keywords = {"API", "User", "Call", "Invoke", "Dll", "Load", "Image", "Module"}
    kernel_keywords = {"Kernel", "Thread", "Process", "Memory", "Handle", "Registry"}
    
    for ev in sorted(all_events):
        b = base_counts.get(ev, 0)
        m = mut_counts.get(ev, 0)
        delta = m - b
        
        classification = "Unchanged" if delta == 0 else ""
        if delta < 0:
            ev_upper = ev.upper()
            if any(kw.upper() in ev_upper for kw in api_keywords):
                classification = "Direct Syscall Evasion"
            elif any(kw.upper() in ev_upper for kw in kernel_keywords):
                classification = "Kernel Evasion (HWBP)"
            else:
                classification = "General Telemetry Loss"
        elif delta > 0:
            classification = "Amplified / Added"

        # Find provider
        provider = "Unknown"
        for e in base_events + mut_events:
            if e.get("event_name") == ev:
                provider = e.get("provider_name", "Unknown")
                break
                
        event_diff.append({
            "event_name": ev,
            "provider": provider,
            "baseline_count": b,
            "mutated_count": m,
            "delta": delta,
            "classification": classification
        })

    return {
        "missing_event_types": missing_types,
        "added_event_types": added_types,
        "missing_providers": missing_providers,
        "provider_reduction_pct": provider_reduction_pct,
        "evasion_categories": evasion_categories,
        "per_provider_metrics": per_provider,
        "total_missing_types": len(missing_types),
        "total_added_types": len(added_types),
        "event_grid": event_diff,
    }


def classify_evasion_layers(missing_events: List[str]) -> Dict[str, List[str]]:
    """Classify missing event types by the evasion layer that caused them.
    
    Categories:
      - Direct Syscall Evasion: Events bypassed by skipping ntdll.dll (API/User-mode markers)
      - Kernel Evasion (HWBP): Events from kernel providers suppressed by debug register redirection
      - General Telemetry Loss: Non-specific loss from instruction mutation or timing obfuscation
    """
    direct_syscall = []
    kernel_hwbp = []
    general_loss = []

    # Classification heuristics based on SilkETW event naming conventions
    api_keywords = {"API", "User", "Call", "Invoke", "Dll", "Load", "Image", "Module"}
    kernel_keywords = {"Kernel", "Thread", "Process", "Memory", "Handle", "Registry"}

    for ev in missing_events:
        ev_upper = ev.upper()
        if any(kw.upper() in ev_upper for kw in api_keywords):
            direct_syscall.append(ev)
        elif any(kw.upper() in ev_upper for kw in kernel_keywords):
            kernel_hwbp.append(ev)
        else:
            general_loss.append(ev)

    return {
        "Direct Syscall Evasion": direct_syscall,
        "Kernel Evasion (HWBP)": kernel_hwbp,
        "General Telemetry Loss": general_loss,
    }
