"""ETWScope -- Active Telemetry Ignorance Measurement Framework.

Usage Mode:
  Capture (Live ETW Capture + Payload Injection + Real-time Measurement):
    python main.py capture --silketw SilkETW.exe --provider Microsoft-Windows-Kernel-Process --payload-i1 poc_injector.exe
"""
import argparse
import sys
import os
import json

# Ensure the local modules can be imported
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from analysis.metrics import load_events_from_file, compute_metrics_from_events
from analysis.trs import TRSEngine, fit_ddf
from analysis.diff_engine import diff_telemetry
from analysis.exporter import export_csv, export_json, export_terminal_report
from analysis.orchestrator import Orchestrator


def run_live(args):
    """Launch live streaming TUI with backend."""
    from frontend.app import ETWScopeApp
    cmd = f"{args.backend} --mock {args.mock}"
    app = ETWScopeApp(backend_cmd=cmd, rules_dir="rules")
    app.run()


def run_analyze(args):
    """Launch TUI in analysis mode. If payload is provided, runs the orchestrator lifecycle first."""
    
    # If payload is provided, this triggers the Orchestrator within the TUI
    if hasattr(args, 'payload') and args.payload:
        args.mutated = args.out
        if hasattr(args, 'target_pid') and args.target_pid:
            args.pid = args.target_pid
        orchestrator_args = args
    else:
        orchestrator_args = None

    from frontend.app import ETWScopeAnalyzeApp
    app = ETWScopeAnalyzeApp(
        baseline_path=args.baseline,
        mutated_path=args.mutated,
        pid_filter=args.pid,
        provider_filter=args.provider,
        orchestrator_args=orchestrator_args
    )
    app.run()


def run_diff(args):
    """Headless batch comparison — outputs TRS, diff, and evasion analysis."""
    print(f"[*] Loading baseline: {args.baseline}")
    base_events = load_events_from_file(args.baseline, pid_filter=args.pid,
                                         provider_filter=args.provider)
    print(f"    -> {len(base_events)} events loaded")

    print(f"[*] Loading mutated:  {args.mutated}")
    mut_events = load_events_from_file(args.mutated, pid_filter=args.pid,
                                        provider_filter=args.provider)
    print(f"    -> {len(mut_events)} events loaded")

    base_metrics = compute_metrics_from_events(base_events)
    mut_metrics = compute_metrics_from_events(mut_events)

    trs_engine = TRSEngine(w1=args.w1, w2=args.w2, w3=args.w3)
    trs_report = trs_engine.compute_full_report(base_metrics, mut_metrics)
    diff_report = diff_telemetry(base_events, mut_events)

    full_report = {
        "trs_report": trs_report,
        "diff": diff_report,
        "ddf": {},
        "baseline_file": os.path.basename(args.baseline),
        "mutated_file": os.path.basename(args.mutated),
    }

    # Print terminal report
    print(export_terminal_report(full_report))

    # Export if requested
    if args.export:
        row = {
            "baseline_file": os.path.basename(args.baseline),
            "mutated_file": os.path.basename(args.mutated),
            "provider": args.provider or "Combined",
            "F_baseline": base_metrics["F"],
            "H_baseline": base_metrics["H"],
            "CV_t_baseline": base_metrics["CV_t"],
            "F_mutated": mut_metrics["F"],
            "H_mutated": mut_metrics["H"],
            "CV_t_mutated": mut_metrics["CV_t"],
            "trs": trs_report["trs"],
            "visibility_pct": trs_report["visibility_pct"],
            "total_missing_types": diff_report["total_missing_types"],
            "evasion_categories": diff_report["evasion_categories"],
            "ddf": {},
        }
        export_csv(args.export, [row], append=True)

    if args.json_out:
        export_json(args.json_out, full_report)


def run_batch(args):
    """Compare baseline against multiple mutated files for DDF curve fitting."""
    print(f"[*] Batch mode: Loading baseline {args.baseline}")
    base_events = load_events_from_file(args.baseline, pid_filter=args.pid,
                                         provider_filter=args.provider)
    base_metrics = compute_metrics_from_events(base_events)
    print(f"    -> {len(base_events)} baseline events")

    # Find all mutated JSON files in the directory
    mut_dir = args.mutated_dir
    mut_files = sorted([f for f in os.listdir(mut_dir)
                        if f.endswith('.json') and not f.startswith('.')])

    if not mut_files:
        print(f"[!] No JSON files found in {mut_dir}")
        return

    print(f"[*] Found {len(mut_files)} mutated logs to compare")

    trs_engine = TRSEngine(w1=args.w1, w2=args.w2, w3=args.w3)
    trs_engine.set_baseline(base_metrics)

    trs_values = []
    all_rows = []

    for i, mf in enumerate(mut_files):
        filepath = os.path.join(mut_dir, mf)
        mut_events = load_events_from_file(filepath, pid_filter=args.pid,
                                            provider_filter=args.provider)
        mut_metrics = compute_metrics_from_events(mut_events)
        trs_report = trs_engine.compute_full_report(base_metrics, mut_metrics)
        diff_report = diff_telemetry(base_events, mut_events)

        trs_val = trs_report["trs"]
        trs_values.append(trs_val)

        print(f"  [{i+1}/{len(mut_files)}] {mf}: TRS={trs_val:.4f} "
              f"(F={mut_metrics['F']}, H={mut_metrics['H']:.4f}, "
              f"Missing={diff_report['total_missing_types']})")

        all_rows.append({
            "baseline_file": os.path.basename(args.baseline),
            "mutated_file": mf,
            "provider": args.provider or "Combined",
            "F_baseline": base_metrics["F"],
            "H_baseline": base_metrics["H"],
            "CV_t_baseline": base_metrics["CV_t"],
            "F_mutated": mut_metrics["F"],
            "H_mutated": mut_metrics["H"],
            "CV_t_mutated": mut_metrics["CV_t"],
            "trs": trs_report["trs"],
            "visibility_pct": trs_report["visibility_pct"],
            "total_missing_types": diff_report["total_missing_types"],
            "evasion_categories": diff_report["evasion_categories"],
        })

    # Fit DDF
    ddf = fit_ddf(trs_values)
    print(f"\n[*] Detection Decay Function (DDF) Fit:")
    print(f"    TRS(I) = {ddf['trs_max']:.4f} * e^(-{ddf['lambda']:.4f} * I) + {ddf['epsilon']:.4f}")
    print(f"    R² = {ddf['r_squared']:.4f}")
    print(f"    Asymptotic Floor (epsilon) = {ddf['epsilon']:.4f}")

    # Add DDF to all rows
    for row in all_rows:
        row["ddf"] = ddf

    if args.export:
        export_csv(args.export, all_rows)

    if args.json_out:
        export_json(args.json_out, {
            "batch_results": all_rows,
            "ddf": ddf,
            "trs_curve": trs_values,
        })





def main():
    parser = argparse.ArgumentParser(
        description="ETWScope: Active Telemetry Ignorance Measurement Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    subparsers = parser.add_subparsers(dest="mode", help="Operating mode")

    # Capture mode (Unified Live Capture + Injection)
    cap_p = subparsers.add_parser("capture", help="Start ETWScope unified terminal capture interface")
    cap_p.add_argument("--silketw", required=True, help="Path to SilkETW.exe")
    cap_p.add_argument("--provider", required=True,
                       help="ETW Provider Name (e.g. Microsoft-Windows-Kernel-Process)")
    cap_p.add_argument("--filter-pid", help="Filter capture to a specific PID (optional)")
    cap_p.add_argument("--baseline", help="Optional baseline JSON for reference comparison")
    cap_p.add_argument("--payload-i1", help="Path to Intensity 1 payload (e.g., standard injection)")
    cap_p.add_argument("--payload-i2", help="Path to Intensity 2 payload (e.g., Direct Syscalls)")
    cap_p.add_argument("--payload-i3", help="Path to Intensity 3 payload (e.g., Indirect Syscalls)")
    cap_p.add_argument("--payload-i4", help="Path to Intensity 4 payload (e.g., HWBP Unhooking)")

    args = parser.parse_args()

    if args.mode == "capture":
        from frontend.app import ETWScopeCaptureApp
        app = ETWScopeCaptureApp(
            silketw_path=args.silketw,
            provider=args.provider,
            baseline_path=args.baseline,
            pid_filter=args.filter_pid,
            payload_i1=args.payload_i1,
            payload_i2=args.payload_i2,
            payload_i3=args.payload_i3,
            payload_i4=args.payload_i4,
        )
        app.run()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
