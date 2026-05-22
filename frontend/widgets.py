from textual.widget import Widget
from textual.app import ComposeResult
from textual.widgets import Static, DataTable, Log
from textual.containers import Container

class DashboardHeader(Static):
    def update_metrics(self, f: int, h: float, cv_t: float, trs: float, total: int):
        self.update(f"🔥 ETWScope | Events Processed: {total} | Window Volume (F): {f} | Entropy (H): {h:.4f} bits | CV_t: {cv_t:.4f} | TRS: {trs:.4f}")

class EventLog(Log):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.max_lines = 1000

class AlertLog(Log):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.max_lines = 500
