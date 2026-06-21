"""Orchestrator Module — Automates SilkETW capture and payload execution.

This module automates the manual workflow of starting a trace, injecting/executing
a mutated payload, stopping the trace gracefully, and returning the log path.
"""
import subprocess
import time
import os
import signal
import sys
from typing import Optional


class Orchestrator:
    def __init__(self, silketw_path: str, logger: callable = None):
        self.silketw_path = silketw_path
        self.capture_process: Optional[subprocess.Popen] = None
        self.log = logger if logger else print

    def start_capture(self, provider: str, out_file: str):
        """Start SilkETW in the background to capture telemetry."""
        if not os.path.exists(self.silketw_path):
            self.log(f"[!] Error: SilkETW not found at {self.silketw_path}")
            return False

        self.log(f"[*] Starting SilkETW capture on provider: {provider}")
        self.log(f"    -> Output will be saved to: {out_file}")

        cmd = [
            self.silketw_path,
            "-t", "user",
            "-pn", provider,
            "-ot", "file",
            "-p", out_file
        ]

        # On Windows, we need CREATE_NEW_PROCESS_GROUP to safely send CTRL_C_EVENT
        kwargs = {}
        if sys.platform == "win32":
            kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP

        try:
            self.capture_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                **kwargs
            )
            # Give SilkETW a few seconds to spin up and hook the provider
            self.log("[*] Waiting 5 seconds for ETW session to initialize...")
            time.sleep(5)
            return True
        except Exception as e:
            self.log(f"[!] Failed to start SilkETW: {e}")
            return False

    def execute_payload(self, payload_path: str, target_pid: Optional[str] = None):
        """Execute the mutated binary test payload."""
        if not os.path.exists(payload_path):
            self.log(f"[!] Error: Payload not found at {payload_path}")
            return False

        self.log(f"[*] Executing target payload: {payload_path}")
        
        cmd = [payload_path]
        if target_pid:
            cmd.append(str(target_pid))

        try:
            # Run payload synchronously and wait for it to finish
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            self.log("\n--- Payload Output ---")
            for line in result.stdout.splitlines():
                self.log(line)
            if result.stderr:
                for line in result.stderr.splitlines():
                    self.log(line)
            self.log("----------------------\n")
            
            # Wait a moment for trailing ETW events to flush
            self.log("[*] Payload execution complete. Waiting 3 seconds for ETW flush...")
            time.sleep(3)
            return True
            
        except subprocess.TimeoutExpired:
            self.log("[!] Payload execution timed out after 30 seconds.")
            return False
        except Exception as e:
            self.log(f"[!] Failed to execute payload: {e}")
            return False

    def stop_capture(self):
        """Gracefully terminate SilkETW to ensure JSON file is fully written."""
        if not self.capture_process:
            return

        self.log("[*] Stopping SilkETW capture trace...")

        try:
            if sys.platform == "win32":
                # Send Ctrl-C to the specific process group we created
                os.kill(self.capture_process.pid, signal.CTRL_C_EVENT)
            else:
                self.capture_process.terminate()

            # Wait for it to close out the file handlers
            try:
                stdout, stderr = self.capture_process.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                self.log("[!] SilkETW did not stop cleanly, forcing kill.")
                self.capture_process.kill()
                
        except Exception as e:
            self.log(f"[!] Error while stopping SilkETW: {e}")
        
        self.capture_process = None
        self.log("[✓] Capture stopped and file finalized.")

    def run_full_cycle(self, provider: str, payload_path: str, out_file: str, target_pid: Optional[str] = None):
        """Helper to run the full capture-execute-stop cycle."""
        if not self.start_capture(provider, out_file):
            return False
        if not self.execute_payload(payload_path, target_pid):
            self.stop_capture()
            return False
        self.stop_capture()
        return True
