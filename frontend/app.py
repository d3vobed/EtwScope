from textual.app import App, ComposeResult
from textual.containers import Vertical, Horizontal
from textual.widgets import Header, Footer, Input
from .widgets import (
    DashboardHeader, AnalyzeHeader, MonitorHeader, EventLog, AlertLog,
    ExecutionTree, EvasionAnalysis, VisibilityScore,
    TelemetryGrid, MathGrid, LiveTelemetryGrid
)
from analysis.metrics import MetricsEngine, load_events_from_file, compute_metrics_from_events
from analysis.trs import TRSEngine, fit_ddf
from analysis.diff_engine import diff_telemetry
from analysis.engine import RuleEngine
from analysis.detector import LiveDetector
import asyncio
import json
import os
import time


class ETWScopeApp(App):
    """Live streaming TUI mode — streams events from the Rust backend."""

    CSS = """
    DashboardHeader {
        background: #1a1a2e;
        color: #00ff88;
        padding: 1;
        text-align: center;
        text-style: bold;
    }
    .panel {
        border: round #444;
        height: 100%;
    }
    #visibility {
        height: 7;
        border: round #444;
        background: #0f0f23;
        color: #e0e0e0;
    }
    """

    def __init__(self, backend_cmd: str, rules_dir: str):
        super().__init__()
        self.backend_cmd = backend_cmd
        self.metrics_engine = MetricsEngine(window_size=1000)
        self.trs_engine = TRSEngine(baseline_f=500, baseline_h=1.5)
        self.rule_engine = RuleEngine(rules_dir=rules_dir)
        self.process = None

    def compose(self) -> ComposeResult:
        yield Header()
        yield DashboardHeader(id="header")
        with Horizontal():
            yield EventLog(id="events", classes="panel")
            with Vertical():
                yield ExecutionTree(id="exec_tree", classes="panel")
                yield EvasionAnalysis(id="evasion", classes="panel")
                yield AlertLog(id="alerts", classes="panel")
                yield VisibilityScore(id="visibility")
        yield Footer()

    async def on_mount(self) -> None:
        self.run_worker(self.run_backend(), exclusive=True)

    async def run_backend(self) -> None:
        self.process = await asyncio.create_subprocess_shell(
            self.backend_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        events_log = self.query_one("#events", EventLog)
        alerts_log = self.query_one("#alerts", AlertLog)
        exec_tree = self.query_one("#exec_tree", ExecutionTree)
        header = self.query_one("#header", DashboardHeader)
        evasion_log = self.query_one("#evasion", EvasionAnalysis)
        vis_score = self.query_one("#visibility", VisibilityScore)

        while True:
            line = await self.process.stdout.readline()
            if not line:
                break

            try:
                event = json.loads(line.decode().strip())
                self.metrics_engine.ingest(event)
                metrics = self.metrics_engine.compute()
                trs = self.trs_engine.compute(metrics)

                header.update_metrics(metrics["F"], metrics["H"], metrics["CV_t"], trs, metrics["total"])
                vis_score.update_score(trs)

                events_log.write_line(
                    f"[{event.get('provider_name')}] PID:{event.get('pid')} {event.get('event_name')}"
                )

                exec_tree.add_event(
                    pid=event.get("pid"),
                    tid=event.get("tid"),
                    event_name=event.get("event_name"),
                    provider=event.get("provider_name")
                )

                provider = event.get("provider_name", "")
                if "Kernel-Audit-API-Calls" in provider:
                    evasion_log.log_evasion(
                        f"[⚠️  SYSCALL] PID:{event.get('pid')} — "
                        f"Direct/Indirect Syscall detected (NTDLL bypass)"
                    )

                alerts = self.rule_engine.evaluate(event)
                for alert in alerts:
                    alerts_log.write_line(
                        f"[!] ALERT: {alert['title']} (Severity: {alert['severity']}) "
                        f"- PID: {alert['pid']}"
                    )

            except Exception:
                pass


class ETWScopeAnalyzeApp(App):
    """Analysis mode TUI — loads baseline + mutated files, computes TRS/DDF, shows diff."""

    CSS = """
    AnalyzeHeader {
        background: #1a1a2e;
        color: #00ccff;
        padding: 1;
        text-align: center;
        text-style: bold;
    }
    .panel {
        border: round #444;
        height: 100%;
    }
    #filter_input {
        dock: top;
        margin: 1;
        border: solid #00ccff;
    }
    #telemetry_grid {
        height: 60%;
        border: round #444;
    }
    #math_grid {
        height: 30%;
        border: round #444;
    }
    #log_panel {
        height: 10%;
        border: round #444;
    }
    """

    def __init__(self, baseline_path: str, mutated_path: str,
                 pid_filter: str = None, provider_filter: str = None,
                 orchestrator_args=None):
        super().__init__()
        self.baseline_path = baseline_path
        self.mutated_path = mutated_path
        self.pid_filter = pid_filter
        self.provider_filter = provider_filter
        self.orchestrator_args = orchestrator_args
        self._full_event_grid = []

    def compose(self) -> ComposeResult:
        yield Header()
        yield AnalyzeHeader(id="header")
        yield Input(placeholder="🔍 Filter Telemetry Diff (e.g. 'NtAllocateVirtualMemory' or 'Direct Syscall')", id="filter_input")
        yield TelemetryGrid(id="telemetry_grid")
        yield MathGrid(id="math_grid")
        yield EvasionAnalysis(id="log_panel")
        yield Footer()

    async def on_input_changed(self, message: Input.Changed) -> None:
        if not hasattr(self, "_full_event_grid") or not self._full_event_grid:
            return
        
        search_term = message.value.lower()
        if not search_term:
            self.query_one("#telemetry_grid", TelemetryGrid).show_diff(self._full_event_grid)
            return
            
        filtered = [
            ev for ev in self._full_event_grid
            if search_term in ev["event_name"].lower() 
            or search_term in ev["classification"].lower()
            or search_term in ev["provider"].lower()
        ]
        self.query_one("#telemetry_grid", TelemetryGrid).show_diff(filtered)

    async def on_mount(self) -> None:
        # Run analysis in background to not block the UI
        self.run_worker(self._run_analysis(), exclusive=True)

    async def _run_analysis(self) -> None:
        header = self.query_one("#header", AnalyzeHeader)
        telemetry_grid = self.query_one("#telemetry_grid", TelemetryGrid)
        math_grid = self.query_one("#math_grid", MathGrid)
        log_panel = self.query_one("#log_panel", EvasionAnalysis)

        # Load events (run in executor to not block event loop)
        import concurrent.futures
        loop = asyncio.get_event_loop()

        # Phase 1: Orchestration (if requested)
        if hasattr(self, 'orchestrator_args') and self.orchestrator_args:
            args = self.orchestrator_args
            from analysis.orchestrator import Orchestrator
            
            import threading
            def safe_log(msg):
                if threading.get_ident() == self._thread_id:
                    log_panel.write_line(msg)
                else:
                    self.call_from_thread(log_panel.write_line, msg)
                
            orch = Orchestrator(args.silketw, logger=safe_log)
            safe_log("=" * 60)
            safe_log(" STCMF Automated Test Runner & Orchestrator")
            safe_log("=" * 60)
            
            with concurrent.futures.ThreadPoolExecutor() as pool:
                success = await loop.run_in_executor(
                    pool,
                    orch.run_full_cycle,
                    args.provider, args.payload, args.mutated, args.pid
                )
                
            if not success:
                log_panel.write_line("[!] Orchestration failed. Aborting analysis.")
                return
                
            log_panel.write_line("\n[*] Initiating Telemetry Diff Analysis...")

        # Phase 2: Analysis
        log_panel.write_line(f"[*] Loading baseline: {self.baseline_path}")

        try:
            with concurrent.futures.ThreadPoolExecutor() as pool:
                base_events = await loop.run_in_executor(
                    pool, load_events_from_file,
                    self.baseline_path, self.pid_filter, self.provider_filter
                )
                log_panel.write_line(f"    -> {len(base_events)} baseline events loaded")

                mut_events = await loop.run_in_executor(
                    pool, load_events_from_file,
                    self.mutated_path, self.pid_filter, self.provider_filter
                )
                log_panel.write_line(f"    -> {len(mut_events)} mutated events loaded")
        except FileNotFoundError as e:
            log_panel.write_line(f"[!] ERROR: File not found - {e}")
            log_panel.write_line("[!] Please check your file paths and try again.")
            return
        except Exception as e:
            log_panel.write_line(f"[!] ERROR loading files: {e}")
            return

        # Compute metrics
        base_metrics = compute_metrics_from_events(base_events)
        mut_metrics = compute_metrics_from_events(mut_events)

        # Compute TRS
        trs_engine = TRSEngine()
        trs_report = trs_engine.compute_full_report(base_metrics, mut_metrics)

        # Run diff
        diff_report = diff_telemetry(base_events, mut_events)

        # Update header
        header.update_report(
            trs=trs_report["trs"],
            vis=trs_report["visibility_pct"],
            base_f=base_metrics["F"],
            mut_f=mut_metrics["F"],
            base_h=base_metrics["H"],
            mut_h=mut_metrics["H"],
            cv_t=mut_metrics["CV_t"],
        )

        # Show Grid Data
        self._full_event_grid = diff_report.get("event_grid", [])
        telemetry_grid.show_diff(self._full_event_grid)
        
        math_grid.show_metrics(
            base_metrics, mut_metrics, trs_report["trs"], trs_report["visibility_pct"]
        )

        log_panel.write_line(f"\n[✓] Analysis complete. TRS = {trs_report['trs']:.4f}")


class ETWScopeMonitorApp(App):
    """Live Passive Monitor — streams ETW events in real-time, classifies
    anomalies, and computes running TRS without requiring a malware sample.
    
    This is the mode that makes ETWScope a true defensive research instrument:
    it sits on the endpoint like Wireshark, captures all ETW events, and
    automatically highlights when something suspicious occurs.
    """

    CSS = """
    MonitorHeader {
        background: #1a1a2e;
        color: #00ff88;
        padding: 1;
        text-align: center;
        text-style: bold;
    }
    #filter_input {
        dock: top;
        margin: 1;
        border: solid #00ff88;
    }
    #live_grid {
        height: 70%;
        border: round #444;
    }
    #log_panel {
        height: 20%;
        border: round #444;
    }
    """

    def __init__(self, silketw_path: str, provider: str,
                 baseline_path: str = None, capture_duration: int = 0):
        super().__init__()
        self.silketw_path = silketw_path
        self.provider = provider
        self.baseline_path = baseline_path
        self.capture_duration = capture_duration  # 0 = indefinite
        self.detector = LiveDetector(baseline_window_seconds=15)
        self._all_events_raw = []
        self._filter_term = ""

    def compose(self) -> ComposeResult:
        yield Header()
        yield MonitorHeader(id="header")
        yield Input(
            placeholder="🔍 Filter live events (e.g. 'ThreadStart' or 'critical')",
            id="filter_input"
        )
        yield LiveTelemetryGrid(id="live_grid")
        yield EvasionAnalysis(id="log_panel")
        yield Footer()

    async def on_input_changed(self, message: Input.Changed) -> None:
        self._filter_term = message.value.lower()

    async def on_mount(self) -> None:
        self.run_worker(self._run_monitor(), exclusive=True)

    async def _run_monitor(self) -> None:
        header = self.query_one("#header", MonitorHeader)
        live_grid = self.query_one("#live_grid", LiveTelemetryGrid)
        log_panel = self.query_one("#log_panel", EvasionAnalysis)

        log_panel.write_line("=" * 60)
        log_panel.write_line(" ETWScope Live Passive Monitor")
        log_panel.write_line("=" * 60)
        log_panel.write_line(f"[*] Provider: {self.provider}")
        log_panel.write_line(f"[*] Detector: Rolling baseline (15s window)")

        # If a baseline JSON is provided, pre-load it
        if self.baseline_path and os.path.exists(self.baseline_path):
            log_panel.write_line(f"[*] Loading reference baseline: {self.baseline_path}")
            try:
                import concurrent.futures
                loop = asyncio.get_event_loop()
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    base_events = await loop.run_in_executor(
                        pool, load_events_from_file, self.baseline_path, None, None
                    )
                log_panel.write_line(f"    -> {len(base_events)} reference events loaded")
            except Exception as e:
                log_panel.write_line(f"[!] Could not load baseline: {e}")

        # Start SilkETW capture to a temp file
        import tempfile
        import subprocess
        import sys

        temp_log = os.path.join(
            tempfile.gettempdir(),
            f"etwscope_live_{int(time.time())}.json"
        )

        log_panel.write_line(f"[*] Starting SilkETW -> {temp_log}")

        cmd = [
            self.silketw_path,
            "-t", "user",
            "-pn", self.provider,
            "-ot", "file",
            "-p", temp_log
        ]

        kwargs = {}
        if sys.platform == "win32":
            kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP

        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, **kwargs
            )
        except Exception as e:
            log_panel.write_line(f"[!] Failed to start SilkETW: {e}")
            log_panel.write_line("[!] Falling back to file-tail mode...")
            proc = None

        log_panel.write_line("[*] Waiting 5 seconds for ETW session to initialize...")
        await asyncio.sleep(5)
        log_panel.write_line("[✓] Live capture started. Streaming events...")
        log_panel.write_line("[*] Building baseline profile (first 15 seconds)...")

        # Tail the JSON file for new events
        from analysis.metrics import _normalise_event

        last_pos = 0
        update_counter = 0
        start_time = time.time()

        try:
            while True:
                # Check if process died
                if proc and proc.poll() is not None:
                    log_panel.write_line("[!] SilkETW process exited unexpectedly.")
                    break

                # Check duration limit
                if self.capture_duration > 0:
                    elapsed = time.time() - start_time
                    if elapsed >= self.capture_duration:
                        log_panel.write_line(f"[✓] Capture duration ({self.capture_duration}s) reached.")
                        break

                # Read new content from the file
                new_events = []
                try:
                    if os.path.exists(temp_log):
                        with open(temp_log, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()

                        if len(content) > last_pos:
                            new_content = content[last_pos:]
                            last_pos = len(content)

                            # Parse JSON objects from new content
                            for line in new_content.splitlines():
                                line = line.strip().rstrip(',').strip('[').strip(']')
                                if line.startswith('{'):
                                    try:
                                        raw = json.loads(line)
                                        event = _normalise_event(raw)
                                        if event:
                                            new_events.append(event)
                                    except json.JSONDecodeError:
                                        continue
                except Exception:
                    pass

                # Process new events
                for event in new_events:
                    risk, color, note = self.detector.classify_event(event)
                    self._all_events_raw.append((event, risk, color, note))

                    # Apply filter
                    if self._filter_term:
                        searchable = (
                            event.get("event_name", "").lower() +
                            event.get("provider_name", "").lower() +
                            risk + note.lower()
                        )
                        if self._filter_term not in searchable:
                            continue

                    live_grid.add_live_event(event, risk, color, note)

                # Update header every 10 iterations
                update_counter += 1
                if update_counter % 5 == 0:
                    trs_data = self.detector.compute_live_trs()
                    stats = self.detector.get_stats()
                    header.update_live(
                        trs=trs_data["trs"],
                        vis=trs_data["visibility_pct"],
                        rate=trs_data["event_rate"],
                        phase=trs_data["phase"],
                        total=stats["total"],
                        suspicious=stats["suspicious"],
                        critical=stats["critical"],
                    )

                    # Log phase transition
                    if trs_data["phase"] == "MONITORING" and update_counter == 5:
                        log_panel.write_line(
                            "[✓] Baseline established. Now detecting anomalies..."
                        )

                await asyncio.sleep(0.5)  # Poll every 500ms

        except asyncio.CancelledError:
            pass
        finally:
            # Cleanup: stop SilkETW
            if proc:
                log_panel.write_line("[*] Stopping SilkETW capture...")
                try:
                    if sys.platform == "win32":
                        import signal
                        os.kill(proc.pid, signal.CTRL_C_EVENT)
                    else:
                        proc.terminate()
                    proc.wait(timeout=5)
                except Exception:
                    proc.kill()
                log_panel.write_line("[✓] Capture stopped.")

            # Final TRS report
            final_trs = self.detector.compute_live_trs()
            stats = self.detector.get_stats()
            log_panel.write_line("")
            log_panel.write_line("=" * 60)
            log_panel.write_line(" FINAL LIVE MONITOR REPORT")
            log_panel.write_line("=" * 60)
            log_panel.write_line(f"  Total Events:     {stats['total']}")
            log_panel.write_line(f"  Normal:           {stats['normal']}")
            log_panel.write_line(f"  Suspicious:       {stats['suspicious']}")
            log_panel.write_line(f"  Critical:         {stats['critical']}")
            log_panel.write_line(f"  Unique PIDs:      {stats['unique_pids']}")
            log_panel.write_line(f"  Event Types:      {stats['unique_event_types']}")
            log_panel.write_line(f"  Final TRS:        {final_trs['trs']:.4f}")
            log_panel.write_line(f"  EDR Visibility:   {final_trs['visibility_pct']:.1f}%")
