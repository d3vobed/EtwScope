from textual.widget import Widget
from textual.app import ComposeResult
from textual.widgets import Static, DataTable, Log, Tree
from textual.containers import Container


class DashboardHeader(Static):
    def update_metrics(self, f: int, h: float, cv_t: float, trs: float, total: int):
        self.update(
            f"🔥 ETWScope | Events: {total} | Volume (F): {f} | "
            f"Entropy (H): {h:.4f} bits | CV_t: {cv_t:.4f} | TRS: {trs:.4f}"
        )


class AnalyzeHeader(Static):
    def update_report(self, trs: float, vis: float, base_f: int, mut_f: int,
                      base_h: float, mut_h: float, cv_t: float):
        self.update(
            f"📊 ETWScope Analysis | TRS: {trs:.4f} | Visibility: {vis:.1f}% | "
            f"Baseline F={base_f} H={base_h:.4f} | Mutated F={mut_f} H={mut_h:.4f} CV_t={cv_t:.4f}"
        )


class EventLog(Log):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.max_lines = 1000


class AlertLog(Log):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.max_lines = 500


class EvasionAnalysis(Log):
    """Real-time evasion layer classification panel."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.max_lines = 200

    def on_mount(self) -> None:
        self.write_line("[*] Evasion Analysis Engine Started")

    def log_evasion(self, msg: str):
        self.write_line(msg)

    def show_categories(self, categories: dict):
        """Display a full evasion breakdown from diff analysis."""
        self.write_line("\n" + "=" * 50)
        self.write_line(" EVASION LAYER CLASSIFICATION")
        self.write_line("=" * 50)
        for layer, events in categories.items():
            count = len(events)
            icon = "🔴" if count > 0 else "🟢"
            self.write_line(f"  {icon} {layer}: {count} event types")
            for ev in events[:8]:
                self.write_line(f"      - {ev}")
            if count > 8:
                self.write_line(f"      ... and {count - 8} more")


class VisibilityScore(Static):
    """Visual gauge showing EDR visibility as a percentage with DDF status."""

    def update_score(self, trs: float, ddf_params: dict = None):
        visibility = min(trs * 100, 100.0)

        if visibility >= 90:
            status = "✅ Full Visibility"
        elif visibility >= 78:
            status = "⚠️ Asymptotic Floor Reached (ε ≈ 0.78)"
        elif visibility >= 50:
            status = "🟡 Significant Decay Present"
        else:
            status = "🔴 Critical EDR Blindspot"

        bar_len = int(visibility / 5)
        bar = "█" * bar_len + "░" * (20 - bar_len)

        content = f"🛡️  Simulated EDR Visibility (Windows Defender / CrowdStrike Falcon)\n"
        content += f"    Score: {visibility:.1f}%  [{bar}]\n"
        content += f"    Status: {status}\n"

        if ddf_params:
            content += (f"    DDF: TRS(I) = {ddf_params.get('trs_max', 0):.3f} × "
                        f"e^(-{ddf_params.get('lambda', 0):.3f}·I) + "
                        f"{ddf_params.get('epsilon', 0):.3f}")

        self.update(content)


class ExecutionTree(Tree):
    """Hierarchical process/thread execution tree."""

    def __init__(self, *args, **kwargs):
        super().__init__("System Execution Flow", *args, **kwargs)
        self.root.expand()
        self.pid_nodes = {}
        self.tid_nodes = {}

    def add_event(self, pid: str, tid: str, event_name: str, provider: str):
        if not pid:
            return

        if pid not in self.pid_nodes:
            if len(self.pid_nodes) > 20:
                return
            node_label = f"▼ Process (PID: {pid})"
            self.pid_nodes[pid] = self.root.add(node_label, expand=True)

        pid_node = self.pid_nodes[pid]

        if tid:
            tid_key = f"{pid}_{tid}"
            if tid_key not in self.tid_nodes:
                if len(self.tid_nodes) > 100:
                    return
                tid_label = f"⚙️ Thread (TID: {tid})"
                self.tid_nodes[tid_key] = pid_node.add(tid_label, expand=True)
            target_node = self.tid_nodes[tid_key]
        else:
            target_node = pid_node

        if len(target_node.children) < 25:
            target_node.add_leaf(f"⚡ {event_name}")


class TelemetryGrid(DataTable):
    """Granular Wireshark-like data grid showing event differentials."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.cursor_type = "row"
        self.zebra_stripes = True

    def on_mount(self) -> None:
        self.add_columns(
            "Event Name / Syscall",
            "Provider",
            "Base (I=0)",
            "Mut (I=x)",
            "Delta (Δ)",
            "Evasion Classification"
        )

    def show_diff(self, event_grid: list):
        self.clear()
        for ev in event_grid:
            delta = ev["delta"]
            delta_str = f"[red]{delta}[/red]" if delta < 0 else f"[green]+{delta}[/green]" if delta > 0 else f"{delta}"
            
            cls_color = "white"
            if "Evasion" in ev["classification"]:
                cls_color = "red bold"
            elif "Loss" in ev["classification"]:
                cls_color = "yellow"
                
            self.add_row(
                ev["event_name"],
                ev["provider"].split("-")[-1] if "-" in ev["provider"] else ev["provider"],
                str(ev["baseline_count"]),
                str(ev["mutated_count"]),
                delta_str,
                f"[{cls_color}]{ev['classification']}[/{cls_color}]"
            )


class MathGrid(DataTable):
    """Grid displaying formal thesis metrics (DDF, TRS)."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.show_header = True

    def on_mount(self) -> None:
        self.add_columns("Metric", "Baseline (I=0)", "Mutated (I=x)", "Degradation / Note")

    def show_metrics(self, base_m: dict, mut_m: dict, trs: float, vis: float):
        self.clear()
        
        # Volume
        f_b, f_m = base_m["F"], mut_m["F"]
        f_deg = f"{(f_m - f_b) / f_b * 100:.1f}%" if f_b else "0%"
        self.add_row("Volume (F)", str(f_b), str(f_m), f_deg)
        
        # Entropy
        h_b, h_m = base_m["H"], mut_m["H"]
        h_deg = f"{(h_m - h_b) / h_b * 100:.1f}%" if h_b else "0%"
        self.add_row("Entropy (H)", f"{h_b:.4f}", f"{h_m:.4f}", h_deg)
        
        # Timing
        cv_b, cv_m = base_m["CV_t"], mut_m["CV_t"]
        cv_deg = f"{(cv_m - cv_b) / cv_b * 100:.1f}%" if cv_b else "0%"
        self.add_row("Timing (CV_t)", f"{cv_b:.4f}", f"{cv_m:.4f}", cv_deg)
        
        # TRS
        self.add_row("Telemetric Risk Score (TRS)", "1.0000", f"{trs:.4f}", f"[bold red]-{(1-trs)*100:.1f}% Visibility[/bold red]")
        
        # DDF
        self.add_row("DDF Asymptotic Floor (ε)", "-", f"{trs:.4f}", "[yellow]Empirical Limit Reached[/yellow]" if trs > 0.7 else "[red]Critical EDR Blindspot[/red]")

