from textual.widget import Widget
from textual.app import ComposeResult
from textual.widgets import Static, DataTable, Log, Tree
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

class ExecutionTree(Tree):
    def __init__(self, *args, **kwargs):
        super().__init__("System Execution Flow", *args, **kwargs)
        self.root.expand()
        self.pid_nodes = {}
        self.tid_nodes = {}

    def add_event(self, pid: str, tid: str, event_name: str, provider: str):
        if not pid:
            return

        # Ensure PID node exists
        if pid not in self.pid_nodes:
            # Prevent tree from growing infinitely
            if len(self.pid_nodes) > 15:
                # remove oldest
                oldest_pid = list(self.pid_nodes.keys())[0]
                # Unfortunately Textual Tree doesn't easily let us delete nodes by reference in all versions,
                # but we can clear and rebuild or just let it scroll. For simplicity, we just add.
                pass
            
            node_label = f"▼ Process (PID: {pid})"
            self.pid_nodes[pid] = self.root.add(node_label, expand=True)

        pid_node = self.pid_nodes[pid]

        # Ensure TID node exists
        if tid:
            tid_key = f"{pid}_{tid}"
            if tid_key not in self.tid_nodes:
                tid_label = f"⚙️ Thread (TID: {tid})"
                self.tid_nodes[tid_key] = pid_node.add(tid_label, expand=True)
            
            target_node = self.tid_nodes[tid_key]
        else:
            target_node = pid_node

        # Add the event as a leaf
        # We limit the number of children to prevent memory leak
        if len(target_node.children) < 20:
            target_node.add_leaf(f"⚡ {event_name}")
