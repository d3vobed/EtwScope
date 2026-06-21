"""ETWScope — Secure Telemetry-Driven Code Mutation Framework Analysis Platform.

Usage Modes:
  Live Stream (TUI):
    python main.py --live --mock <etw_log.json>
    
  Analyze (TUI with diff):
    python main.py --analyze <baseline.json> <mutated.json>

  Automated Test Runner (Windows only):
    python main.py run-test --silketw "C:\\SilkETW.exe" --provider "Microsoft-Windows-Kernel-Process" --payload "C:\\tb_inject.exe" --baseline "baseline.json" --out "mutated.json"

  Batch Diff (headless, for Chapter 4 results):
    python main.py --diff <baseline.json> <mutated.json> --export results.csv

  Batch Multi (compare baseline against multiple mutation intensities):
    python main.py --batch <baseline.json> --mutated-dir <dir_of_mutated_jsons/> --export results.csv
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
    """Launch TUI in analysis mode showing baseline vs mutated comparison."""
    from frontend.app import ETWScopeAnalyzeApp
    app = ETWScopeAnalyzeApp(
        baseline_path=args.baseline,
        mutated_path=args.mutated,
        pid_filter=args.pid,
        provider_filter=args.provider,
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


def run_orchestrator_mode(args):
    """Run the automated capture -> inject -> measure workflow directly inside the TUI."""
    args.mutated = args.out  # set the output file as mutated
    args.pid = args.target_pid  # Pass the target_pid to the pid filter
    
    from frontend.app import ETWScopeAnalyzeApp
    app = ETWScopeAnalyzeApp(
        baseline_path=args.baseline,
        mutated_path=args.mutated,
        pid_filter=args.pid,
        provider_filter=args.provider,
        orchestrator_args=args
    )
    app.run()


def main():
    parser = argparse.ArgumentParser(
        description="ETWScope: Secure Telemetry-Driven Code Mutation Framework Analysis Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    subparsers = parser.add_subparsers(dest="mode", help="Operating mode")

    # Live mode
    live_p = subparsers.add_parser("live", help="Live streaming TUI")
    live_p.add_argument("--mock", required=True, help="Path to JSON file to stream")
    live_p.add_argument("--backend", default="backend/target/release/etwscope_backend",
                        help="Path to rust backend executable")

    # Analyze mode (TUI with diff)
    analyze_p = subparsers.add_parser("analyze", help="TUI analysis of baseline vs mutated")
    analyze_p.add_argument("baseline", help="Path to baseline ETW JSON log")
    analyze_p.add_argument("mutated", help="Path to mutated ETW JSON log")
    analyze_p.add_argument("--pid", help="Filter by Process ID")
    analyze_p.add_argument("--provider", help="Filter by ETW provider name")

    # Diff mode (headless)
    diff_p = subparsers.add_parser("diff", help="Headless diff with TRS computation")
    diff_p.add_argument("baseline", help="Path to baseline ETW JSON log")
    diff_p.add_argument("mutated", help="Path to mutated ETW JSON log")
    diff_p.add_argument("--pid", help="Filter by Process ID")
    diff_p.add_argument("--provider", help="Filter by ETW provider name")
    diff_p.add_argument("--export", help="Export results to CSV file")
    diff_p.add_argument("--json-out", help="Export full report to JSON")
    diff_p.add_argument("--w1", type=float, default=0.45, help="TRS volume weight")
    diff_p.add_argument("--w2", type=float, default=0.35, help="TRS entropy weight")
    diff_p.add_argument("--w3", type=float, default=0.20, help="TRS timing weight")

    # Batch mode (multiple intensities -> DDF)
    batch_p = subparsers.add_parser("batch", help="Batch comparison for DDF curve fitting")
    batch_p.add_argument("baseline", help="Path to baseline ETW JSON log")
    batch_p.add_argument("--mutated-dir", required=True,
                         help="Directory containing mutated JSON logs")
    batch_p.add_argument("--pid", help="Filter by Process ID")
    batch_p.add_argument("--provider", help="Filter by ETW provider name")
    batch_p.add_argument("--export", help="Export results to CSV file")
    batch_p.add_argument("--json-out", help="Export full report to JSON")
    batch_p.add_argument("--w1", type=float, default=0.45, help="TRS volume weight")
    batch_p.add_argument("--w2", type=float, default=0.35, help="TRS entropy weight")
    batch_p.add_argument("--w3", type=float, default=0.20, help="TRS timing weight")

    # Orchestrator / Test Runner mode
    run_p = subparsers.add_parser("run-test", help="Automated Orchestrator (Capture -> Inject -> Measure)")
    run_p.add_argument("--silketw", required=True, help="Path to SilkETW.exe")
    run_p.add_argument("--provider", required=True, help="ETW Provider Name (e.g. Microsoft-Windows-Kernel-Process)")
    run_p.add_argument("--payload", required=True, help="Path to the mutated payload exe to run")
    run_p.add_argument("--target-pid", help="Target PID to pass to payload (optional)")
    run_p.add_argument("--baseline", required=True, help="Path to baseline JSON for comparison")
    run_p.add_argument("--out", required=True, help="Path to output the generated JSON")
    run_p.add_argument("--export", help="Export results to CSV file")
    run_p.add_argument("--json-out", help="Export full report to JSON")
    run_p.add_argument("--w1", type=float, default=0.45, help="TRS volume weight")
    run_p.add_argument("--w2", type=float, default=0.35, help="TRS entropy weight")
    run_p.add_argument("--w3", type=float, default=0.20, help="TRS timing weight")

    args = parser.parse_args()

    if args.mode == "live":
        run_live(args)
    elif args.mode == "analyze":
        run_analyze(args)
    elif args.mode == "diff":
        run_diff(args)
    elif args.mode == "batch":
        run_batch(args)
    elif args.mode == "run-test":
        run_orchestrator_mode(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
