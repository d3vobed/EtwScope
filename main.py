"""ETWScope -- Active Telemetry Ignorance Measurement Framework.

Usage Modes:
  capture  : Live ETW capture + payload injection + real-time measurement
  analyze  : Headless batch comparison of baseline vs mutated JSON logs

Examples:
  python main.py capture --silketw SilkETW.exe --provider Microsoft-Windows-Kernel-Process
  python main.py analyze --baseline clean.json --mutated mut_I1.json
"""
import argparse
import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from analysis.metrics import load_events_from_file, compute_metrics_from_events
from analysis.trs import TRSEngine, fit_ddf
from analysis.diff_engine import diff_telemetry
from analysis.exporter import export_csv, export_json, export_terminal_report


# ---------------------------------------------------------------------------
# Mode: capture  (unified live TUI)
# ---------------------------------------------------------------------------
def run_capture(args):
    """Launch the unified active capture terminal interface."""
    from frontend.app import ETWScopeCaptureApp
    app = ETWScopeCaptureApp(
        provider=args.provider,
        silketw_path=args.silketw,
        log_file=args.log_file,
        baseline_path=args.baseline,
        pid_filter=args.filter_pid,
        payload_i1=args.payload_i1,
        payload_i2=args.payload_i2,
        payload_i3=args.payload_i3,
        payload_i4=args.payload_i4,
    )
    app.run()


# ---------------------------------------------------------------------------
# Mode: analyze  (headless single comparison)
# ---------------------------------------------------------------------------
def run_analyze(args):
    """Headless batch comparison -- outputs TRS, diff, and evasion analysis."""
    print(f"[*] Loading baseline: {args.baseline}")
    base_events = load_events_from_file(
        args.baseline, pid_filter=args.pid, provider_filter=args.provider)
    print(f"    -> {len(base_events)} events loaded")

    print(f"[*] Loading mutated:  {args.mutated}")
    mut_events = load_events_from_file(
        args.mutated, pid_filter=args.pid, provider_filter=args.provider)
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

    print(export_terminal_report(full_report))

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


# ---------------------------------------------------------------------------
# Mode: batch  (multi-file DDF curve fitting)
# ---------------------------------------------------------------------------
def run_batch(args):
    """Compare baseline against multiple mutated files for DDF curve fitting."""
    print(f"[*] Batch mode: Loading baseline {args.baseline}")
    base_events = load_events_from_file(
        args.baseline, pid_filter=args.pid, provider_filter=args.provider)
    base_metrics = compute_metrics_from_events(base_events)
    print(f"    -> {len(base_events)} baseline events")

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
        mut_events = load_events_from_file(
            filepath, pid_filter=args.pid, provider_filter=args.provider)
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

    ddf = fit_ddf(trs_values)
    print(f"\n[*] Detection Decay Function (DDF) Fit:")
    print(f"    TRS(I) = {ddf['trs_max']:.4f} * e^(-{ddf['lambda']:.4f} * I) + {ddf['epsilon']:.4f}")
    print(f"    R^2 = {ddf['r_squared']:.4f}")
    print(f"    Asymptotic Floor (epsilon) = {ddf['epsilon']:.4f}")

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


# ---------------------------------------------------------------------------
# CLI Parser
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="ETWScope: Active Telemetry Ignorance Measurement Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    subparsers = parser.add_subparsers(dest="mode", help="Operating mode")

    # -- capture -----------------------------------------------------------
    cap = subparsers.add_parser(
        "capture",
        help="Live ETW capture with real-time injection and measurement")
    cap.add_argument("--silketw",
                     help="Path to SilkETW.exe (if launching from python)")
    cap.add_argument("--log-file",
                     help="Path to existing SilkETW JSON log (if running SilkETW externally)")
    cap.add_argument("--provider", required=True,
                     help="ETW Provider (e.g. Microsoft-Windows-Kernel-Process)")
    cap.add_argument("--filter-pid",
                     help="Optional: filter capture to a specific PID")
    cap.add_argument("--baseline",
                     help="Optional: baseline JSON for reference comparison")
    cap.add_argument("--payload-i1",
                     help="Intensity 1 payload (Win32 API baseline)")
    cap.add_argument("--payload-i2",
                     help="Intensity 2 payload (Direct Syscalls)")
    cap.add_argument("--payload-i3",
                     help="Intensity 3 payload (Indirect Syscalls)")
    cap.add_argument("--payload-i4",
                     help="Intensity 4 payload (HWBP Unhooking)")

    # -- analyze -----------------------------------------------------------
    ana = subparsers.add_parser(
        "analyze",
        help="Headless comparison of baseline vs mutated JSON logs")
    ana.add_argument("--baseline", required=True,
                     help="Baseline ETW JSON log")
    ana.add_argument("--mutated", required=True,
                     help="Mutated ETW JSON log")
    ana.add_argument("--pid",
                     help="Filter by PID")
    ana.add_argument("--provider",
                     help="Filter by ETW provider name")
    ana.add_argument("--w1", type=float, default=0.45,
                     help="TRS weight for volume (default: 0.45)")
    ana.add_argument("--w2", type=float, default=0.35,
                     help="TRS weight for entropy (default: 0.35)")
    ana.add_argument("--w3", type=float, default=0.20,
                     help="TRS weight for timing (default: 0.20)")
    ana.add_argument("--export",
                     help="Export results to CSV file")
    ana.add_argument("--json-out",
                     help="Export full report as JSON")

    # -- batch -------------------------------------------------------------
    bat = subparsers.add_parser(
        "batch",
        help="Compare baseline against a directory of mutated logs (DDF fitting)")
    bat.add_argument("--baseline", required=True,
                     help="Baseline ETW JSON log")
    bat.add_argument("--mutated-dir", required=True,
                     help="Directory of mutated JSON logs")
    bat.add_argument("--pid",
                     help="Filter by PID")
    bat.add_argument("--provider",
                     help="Filter by ETW provider name")
    bat.add_argument("--w1", type=float, default=0.45)
    bat.add_argument("--w2", type=float, default=0.35)
    bat.add_argument("--w3", type=float, default=0.20)
    bat.add_argument("--export",
                     help="Export results to CSV file")
    bat.add_argument("--json-out",
                     help="Export full report as JSON")

    args = parser.parse_args()

    if args.mode == "capture":
        run_capture(args)
    elif args.mode == "analyze":
        run_analyze(args)
    elif args.mode == "batch":
        run_batch(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
