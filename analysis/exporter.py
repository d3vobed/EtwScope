"""Result Exporter — Outputs structured results for Chapter 4 tables.

Exports to CSV, JSON, and formatted text reports.
"""
import csv
import json
import os
from datetime import datetime
from typing import Dict, Any, List, Optional


def export_csv(filepath: str, results: List[Dict[str, Any]], append: bool = False):
    """Export TRS comparison results to CSV.
    
    Each row: baseline_file, mutated_file, provider, F_base, H_base, CV_t_base,
              F_mut, H_mut, CV_t_mut, TRS, visibility_pct, missing_events, evasion_layer
    """
    mode = 'a' if append else 'w'
    write_header = not (append and os.path.exists(filepath))

    with open(filepath, mode, newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        if write_header:
            writer.writerow([
                "Timestamp", "Baseline_File", "Mutated_File", "Provider",
                "F_baseline", "H_baseline", "CV_t_baseline",
                "F_mutated", "H_mutated", "CV_t_mutated",
                "TRS", "Visibility_Pct",
                "Missing_Event_Types", "Direct_Syscall_Evasion",
                "Kernel_HWBP_Evasion", "General_Loss",
                "Lambda", "Epsilon"
            ])

        for r in results:
            evasion = r.get("evasion_categories", {})
            ddf = r.get("ddf", {})
            writer.writerow([
                datetime.now().isoformat(),
                r.get("baseline_file", ""),
                r.get("mutated_file", ""),
                r.get("provider", "Combined"),
                r.get("F_baseline", 0),
                r.get("H_baseline", 0.0),
                r.get("CV_t_baseline", 0.0),
                r.get("F_mutated", 0),
                r.get("H_mutated", 0.0),
                r.get("CV_t_mutated", 0.0),
                r.get("trs", 0.0),
                r.get("visibility_pct", 0.0),
                r.get("total_missing_types", 0),
                len(evasion.get("Direct Syscall Evasion", [])),
                len(evasion.get("Kernel Evasion (HWBP)", [])),
                len(evasion.get("General Telemetry Loss", [])),
                ddf.get("lambda", ""),
                ddf.get("epsilon", ""),
            ])

    print(f"[+] CSV results exported to {filepath}")


def export_json(filepath: str, report: Dict[str, Any]):
    """Export full analysis report to JSON."""
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] JSON report exported to {filepath}")


def export_terminal_report(report: Dict[str, Any]) -> str:
    """Generate a formatted terminal report string."""
    lines = []
    lines.append("=" * 70)
    lines.append(" ETWScope Telemetry Analysis Report")
    lines.append("=" * 70)

    trs_data = report.get("trs_report", {})
    lines.append(f"\n  Telemetry Resilience Score (TRS): {trs_data.get('trs', 0):.4f}")
    lines.append(f"  EDR Visibility: {trs_data.get('visibility_pct', 0):.1f}%")

    lines.append(f"\n  Volume Ratio  (w1={trs_data.get('weights', {}).get('w1', 0.45)}): "
                 f"{trs_data.get('volume_ratio', 0):.4f}")
    lines.append(f"  Entropy Ratio (w2={trs_data.get('weights', {}).get('w2', 0.35)}): "
                 f"{trs_data.get('entropy_ratio', 0):.4f}")
    lines.append(f"  Timing Comp.  (w3={trs_data.get('weights', {}).get('w3', 0.20)}): "
                 f"{trs_data.get('timing_component', 0):.4f}")

    lines.append(f"\n  Baseline: F={trs_data.get('baseline', {}).get('F', 0)}, "
                 f"H={trs_data.get('baseline', {}).get('H', 0):.4f} bits")
    lines.append(f"  Mutated:  F={trs_data.get('mutated', {}).get('F', 0)}, "
                 f"H={trs_data.get('mutated', {}).get('H', 0):.4f} bits, "
                 f"CV_t={trs_data.get('mutated', {}).get('CV_t', 0):.4f}")

    diff_data = report.get("diff", {})
    lines.append(f"\n  Missing Event Types: {diff_data.get('total_missing_types', 0)}")
    lines.append(f"  Added Event Types:   {diff_data.get('total_added_types', 0)}")
    lines.append(f"  Provider Reduction:  {diff_data.get('provider_reduction_pct', 0):.1f}%")

    evasion = diff_data.get("evasion_categories", {})
    lines.append("\n  Evasion Layer Breakdown:")
    for layer, events in evasion.items():
        if events:
            lines.append(f"    [{layer}]: {len(events)} event types")
            for ev in events[:5]:
                lines.append(f"      - {ev}")
            if len(events) > 5:
                lines.append(f"      ... and {len(events) - 5} more")

    ddf = report.get("ddf", {})
    if ddf:
        lines.append(f"\n  Detection Decay Function (DDF):")
        lines.append(f"    TRS_max = {ddf.get('trs_max', 0):.4f}")
        lines.append(f"    Lambda  = {ddf.get('lambda', 0):.4f}")
        lines.append(f"    Epsilon = {ddf.get('epsilon', 0):.4f} (Asymptotic Floor)")
        lines.append(f"    R²      = {ddf.get('r_squared', 0):.4f}")

    lines.append("\n" + "=" * 70)
    return "\n".join(lines)
