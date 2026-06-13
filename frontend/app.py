from textual.app import App, ComposeResult
from textual.containers import Vertical, Horizontal
from textual.widgets import Header, Footer
from .widgets import DashboardHeader, EventLog, AlertLog, ExecutionTree
from analysis.metrics import MetricsEngine
from analysis.trs import TRSEngine
from analysis.engine import RuleEngine
import asyncio
import json

class ETWScopeApp(App):
    CSS = """
    DashboardHeader {
        background: #2b2b2b;
        color: #00ff00;
        padding: 1;
        text-align: center;
        text-style: bold;
    }
    .panel {
        border: round #555;
        height: 100%;
    }
    """

    def __init__(self, backend_cmd: str, rules_dir: str):
        super().__init__()
        self.backend_cmd = backend_cmd
        self.metrics_engine = MetricsEngine(window_size=1000)
        
        # In a real app, you'd calculate a clean baseline first. 
        # Using placeholder baseline metrics for TRS computation.
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
                yield AlertLog(id="alerts", classes="panel")
        yield Footer()

    async def on_mount(self) -> None:
        asyncio.create_task(self.run_backend())

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
                
                # Log event
                events_log.write_line(f"[{event.get('provider_name')}] PID:{event.get('pid')} {event.get('event_name')}")
                
                # Add to Execution Tree
                exec_tree.add_event(
                    pid=event.get("pid"),
                    tid=event.get("tid"),
                    event_name=event.get("event_name"),
                    provider=event.get("provider_name")
                )
                
                # Check rules
                alerts = self.rule_engine.evaluate(event)
                for alert in alerts:
                    alerts_log.write_line(f"[!] ALERT: {alert['title']} (Severity: {alert['severity']}) - PID: {alert['pid']}")
                    
            except Exception as e:
                pass
