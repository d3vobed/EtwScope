from textual.app import App, ComposeResult
from textual.containers import Vertical, Horizontal, Container
from textual.widgets import Header, Footer, Input
from .widgets import (
    DashboardHeader, AnalyzeHeader, MonitorHeader, EventLog, AlertLog,
    TelemetryGrid, MathGrid, LiveTelemetryGrid, MeasurementConsole, MutationTracker
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



class ETWScopeCaptureApp(App):
    """
    Unified active capture terminal interface.
    Strips away UI panes to provide a pure Wireshark-like event stream
    combined with a mathematical Ignorance Measurement console at the bottom.
    """

    BINDINGS = [
        ("1", "inject_payload_1", "Inject I1"),
        ("2", "inject_payload_2", "Inject I2"),
        ("3", "inject_payload_3", "Inject I3"),
        ("4", "inject_payload_4", "Inject I4"),
        ("space", "toggle_capture", "Start Active Capture"),
    ]

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
    #main_pane {
        height: 70%;
        border: round #444;
    }
    #live_grid {
        width: 75%;
        height: 100%;
        border-right: solid #444;
    }
    #mutation_tracker {
        width: 25%;
        height: 100%;
        padding: 1;
        background: #111122;
    }
    #bottom_pane {
        height: 30%;
        border: round #444;
    }
    #log_panel {
        width: 100%;
        height: 100%;
    }
    """

    def __init__(self, silketw_path: str, provider: str,
                 baseline_path: str = None, pid_filter: str = None,
                 payload_i1: str = None, payload_i2: str = None, 
                 payload_i3: str = None, payload_i4: str = None):
        super().__init__()
        self.silketw_path = silketw_path
        self.provider = provider
        self.baseline_path = baseline_path
        self.pid_filter = pid_filter
        self.payload_i1 = payload_i1
        self.payload_i2 = payload_i2
        self.payload_i3 = payload_i3
        self.payload_i4 = payload_i4
        self.detector = LiveDetector()
        self._all_events_raw = []
        self._filter_term = ""

    def compose(self) -> ComposeResult:
        yield Header()
        yield MonitorHeader(id="header")
        yield Input(
            placeholder="🔍 Filter live events (e.g. 'ThreadStart' or 'critical')",
            id="filter_input"
        )
        with Horizontal(id="main_pane"):
            yield LiveTelemetryGrid(id="live_grid")
            yield MutationTracker(id="mutation_tracker")
        with Container(id="bottom_pane"):
            yield MeasurementConsole(id="log_panel")
        yield Footer()

    async def action_toggle_capture(self) -> None:
        if not self.detector.baseline_established:
            warning = self.detector.trigger_active_capture()
            log_panel = self.query_one("#log_panel", MeasurementConsole)
            if warning:
                log_panel.write_line("\n[bold red][WARN] BASELINE APPEARS POISONED![/bold red]")
                log_panel.write_line(f"[bold red]   -> {warning}[/bold red]")
                log_panel.write_line("[bold yellow]   -> Proceeding with active capture, but results may be skewed.[/bold yellow]")
            else:
                log_panel.write_line("\n[bold green][OK] BASELINE LOCKED. ACTIVE CAPTURE STARTED.[/bold green]")
                log_panel.write_line("   -> Now analyzing events for evasion anomalies...")

    async def action_inject_payload_1(self) -> None:
        await self._trigger_payload(self.payload_i1, "Intensity 1 (Baseline Injection)")

    async def action_inject_payload_2(self) -> None:
        await self._trigger_payload(self.payload_i2, "Intensity 2 (Direct Syscall)")

    async def action_inject_payload_3(self) -> None:
        await self._trigger_payload(self.payload_i3, "Intensity 3 (Indirect Syscall)")
        
    async def action_inject_payload_4(self) -> None:
        await self._trigger_payload(self.payload_i4, "Intensity 4 (HWBP Unhooking)")

    async def _trigger_payload(self, path: str, name: str) -> None:
        log_panel = self.query_one("#log_panel", MeasurementConsole)
        tracker = self.query_one("#mutation_tracker", MutationTracker)
        
        if not path:
            log_panel.write_line(f"[!] {name} payload path not provided via CLI. Use --payload-iX")
            return
        if not os.path.exists(path):
            log_panel.write_line(f"[!] Payload not found at {path}")
            return

        log_panel.write_line(f"\n[bold red][EXEC] INJECTING {name}[/bold red]")
        log_panel.write_line(f"   -> Executing: {path}")
        
        try:
            import subprocess
            proc = subprocess.Popen([path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            log_panel.write_line("   -> Process launched asynchronously.")
            
            # Reset the visual tracker for the new target
            tracker.reset_tracker(pid=str(proc.pid))
            self.detector.set_active_tracker(tracker)
            
        except Exception as e:
            log_panel.write_line(f"[!] Failed to launch payload: {e}")

    async def on_input_changed(self, message: Input.Changed) -> None:
        self._filter_term = message.value.lower()

    async def on_mount(self) -> None:
        self.run_worker(self._run_capture())

    async def _run_capture(self) -> None:
        header = self.query_one("#header", MonitorHeader)
        live_grid = self.query_one("#live_grid", LiveTelemetryGrid)
        log_panel = self.query_one("#log_panel", MeasurementConsole)

        log_panel.write_line("=" * 60)
        log_panel.write_line(" ETWScope Active Measurement Terminal")
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
        import ctypes

        # -- Check admin privileges (SilkETW requires them for ETW sessions) --
        is_admin = False
        if sys.platform == "win32":
            try:
                is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            except Exception:
                is_admin = False
            if not is_admin:
                log_panel.write_line("[bold red][WARN] NOT RUNNING AS ADMINISTRATOR![/bold red]")
                log_panel.write_line("[bold red]   -> SilkETW requires admin privileges to create ETW sessions.[/bold red]")
                log_panel.write_line("[bold yellow]   -> Right-click your terminal and select 'Run as Administrator'.[/bold yellow]")

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
        log_panel.write_line(f"[*] CMD: {' '.join(cmd)}")

        kwargs = {}
        if sys.platform == "win32":
            kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP

        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, **kwargs
            )
        except FileNotFoundError:
            log_panel.write_line(f"[bold red][!] SilkETW not found at: {self.silketw_path}[/bold red]")
            log_panel.write_line("[!] Check the --silketw path and try again.")
            proc = None
        except Exception as e:
            log_panel.write_line(f"[bold red][!] Failed to start SilkETW: {e}[/bold red]")
            proc = None

        log_panel.write_line("[*] Waiting 5 seconds for ETW session to initialize...")
        await asyncio.sleep(5)

        # -- Check if SilkETW survived the startup --
        if proc and proc.poll() is not None:
            exit_code = proc.returncode
            stderr_out = ""
            stdout_out = ""
            try:
                stdout_out = proc.stdout.read()
                stderr_out = proc.stderr.read()
            except Exception:
                pass
            log_panel.write_line(f"[bold red][!] SilkETW exited during startup (exit code: {exit_code})[/bold red]")
            if stderr_out:
                for line in stderr_out.strip().splitlines()[:10]:
                    log_panel.write_line(f"[red]   STDERR: {line}[/red]")
            if stdout_out:
                for line in stdout_out.strip().splitlines()[:10]:
                    log_panel.write_line(f"[yellow]   STDOUT: {line}[/yellow]")
            if not is_admin:
                log_panel.write_line("[bold yellow]   -> This is likely because you need Administrator privileges.[/bold yellow]")
            log_panel.write_line("[*] Continuing in monitoring mode (no live ETW feed)...")
            proc = None

        if proc:
            log_panel.write_line("[bold green][OK] SilkETW is running. Live capture active. LEARNING BASELINE...[/bold green]")
        else:
            log_panel.write_line("[bold yellow][OK] Running without SilkETW. You can still inject payloads to test.[/bold yellow]")
        log_panel.write_line("[*] Let the system run normally to build a profile.")
        log_panel.write_line("[*] Press [bold]SPACEBAR[/bold] when ready to start Active Capture.")

        # Tail the JSON file for new events
        from analysis.metrics import _normalise_event

        last_pos = 0
        update_counter = 0
        start_time = time.time()

        try:
            while True:
                # Check if process died
                if proc and proc.poll() is not None:
                    stderr_msg = ""
                    try:
                        stderr_msg = proc.stderr.read()
                    except Exception:
                        pass
                    log_panel.write_line("[bold red][!] SilkETW process exited unexpectedly.[/bold red]")
                    if stderr_msg:
                        for errline in stderr_msg.strip().splitlines()[:5]:
                            log_panel.write_line(f"[red]   STDERR: {errline}[/red]")
                    proc = None
                    # Don't break — keep the UI alive so user can still interact

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
                    if self.pid_filter and event.get("pid") != self.pid_filter:
                        continue

                    risk, color, note = self.detector.classify_event(event)
                    self._all_events_raw.append((event, risk, color, note))

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
                log_panel.write_line("[OK] Capture stopped.")

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
