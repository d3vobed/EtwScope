import yaml
from typing import List, Dict, Any
import os

class RuleEngine:
    def __init__(self, rules_dir: str):
        self.rules = []
        self.load_rules(rules_dir)
        # Track sequences per PID
        # pid -> provider -> list of seen events
        self.state = {}

    def load_rules(self, rules_dir: str):
        if not os.path.exists(rules_dir):
            return
        for file in os.listdir(rules_dir):
            if file.endswith((".yaml", ".yml")):
                with open(os.path.join(rules_dir, file), 'r') as f:
                    try:
                        rule = yaml.safe_load(f)
                        self.rules.append(rule)
                    except Exception as e:
                        print(f"Failed to load rule {file}: {e}")

    def evaluate(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        alerts = []
        pid = event.get("pid")
        if not pid:
            return alerts
            
        provider = event.get("provider_name")
        event_name = event.get("event_name")
        
        if pid not in self.state:
            self.state[pid] = {}
        if provider not in self.state[pid]:
            self.state[pid][provider] = []
            
        self.state[pid][provider].append(event_name)
        # Keep recent history
        if len(self.state[pid][provider]) > 50:
            self.state[pid][provider].pop(0)
            
        history = self.state[pid][provider]

        for rule in self.rules:
            r_provider = rule.get("provider")
            if r_provider and r_provider != provider:
                continue
                
            sequence = rule.get("match", [])
            if not sequence:
                continue
                
            # Check if sequence exists in history in order
            seq_idx = 0
            for h_event in history:
                if h_event == sequence[seq_idx]:
                    seq_idx += 1
                    if seq_idx == len(sequence):
                        # Match found!
                        alerts.append({
                            "title": rule.get("title", "Unknown Alert"),
                            "severity": rule.get("severity", "info"),
                            "pid": pid,
                            "trigger_event": event_name
                        })
                        # Reset history so we don't spam
                        self.state[pid][provider] = []
                        break

        return alerts
