import subprocess
import json
import time
import threading
from datetime import datetime
from .chain import LogChain

class RealLogCollector:
    """
    Fetches ACTUAL Windows Event Logs and Running Processes in Real-Time.
    Uses PowerShell to query:
      - Application Event Logs
      - System Event Logs
      - Security Event Logs (if admin)
      - Currently Running Processes (CPU, Memory, PID)
    """
    def __init__(self, log_chain: LogChain):
        self.chain = log_chain
        self.last_event_times = {
            "Application": None,
            "System": None,
        }
        self.seen_pids = set()
        self._running = False
        self._thread = None
        self.events_captured = 0

    def start(self, duration=120):
        """Start Windows log collection in a background thread."""
        if self._running:
            return
        self._running = True
        self.events_captured = 0
        self._thread = threading.Thread(target=self._collection_worker, args=(duration,), daemon=True)
        self._thread.start()

    def stop(self):
        """Stop the collection."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=3)
            self._thread = None

    def _collection_worker(self, duration=120):
        """Main collection loop — fetches from multiple sources."""
        start_time = time.time()
        cycle = 0

        while self._running and (time.time() - start_time) < duration:
            try:
                # Alternate between different log sources each cycle
                if cycle % 3 == 0:
                    self._fetch_event_log("Application")
                elif cycle % 3 == 1:
                    self._fetch_event_log("System")
                else:
                    self._fetch_running_processes()

                cycle += 1
            except Exception as e:
                print(f"[Collector Error] {e}")

            time.sleep(1.5)

        self._running = False

    def _fetch_event_log(self, log_name="Application"):
        """
        Calls PowerShell to get the newest event(s) from the specified log.
        """
        ps_command = (
            f"Get-EventLog -LogName {log_name} -Newest 3 "
            f"| Select-Object EntryType, Source, Message, TimeGenerated, EventID, InstanceId "
            f"| ConvertTo-Json"
        )

        try:
            result = subprocess.run(
                ["powershell", "-Command", ps_command],
                capture_output=True, text=True, timeout=10
            )

            if result.returncode != 0 or not result.stdout.strip():
                return

            data = json.loads(result.stdout)

            # Ensure data is always a list
            if isinstance(data, dict):
                data = [data]

            for event in data:
                time_gen = str(event.get('TimeGenerated', ''))

                # Dedup: skip if already seen
                if self.last_event_times.get(log_name) == time_gen:
                    continue

                self.last_event_times[log_name] = time_gen

                source = event.get('Source', 'Unknown')
                entry_type = str(event.get('EntryType', 'Information'))
                event_id = event.get('EventID', '')
                message = str(event.get('Message', ''))[:120]

                # Map severity
                severity = "INFO"
                if "Error" in entry_type:
                    severity = "ERROR"
                elif "Warning" in entry_type:
                    severity = "WARNING"

                full_message = f"[{log_name}] EventID:{event_id} {message}"

                self.chain.add_log(
                    source=f"{source} ({log_name})",
                    event_type="WIN_EVENT",
                    message=full_message,
                    severity=severity
                )
                self.events_captured += 1
                break  # Only add the newest unseen event per call

        except subprocess.TimeoutExpired:
            pass
        except Exception as e:
            pass

    def _fetch_running_processes(self):
        """
        Fetches top running Windows processes with CPU/Memory info.
        Captures new processes that weren't seen before.
        """
        ps_command = (
            "Get-Process | Sort-Object -Property CPU -Descending "
            "| Select-Object -First 10 Id, ProcessName, CPU, "
            "@{Name='MemMB';Expression={[math]::Round($_.WorkingSet64/1MB,1)}}, "
            "StartTime "
            "| ConvertTo-Json"
        )

        try:
            result = subprocess.run(
                ["powershell", "-Command", ps_command],
                capture_output=True, text=True, timeout=10
            )

            if result.returncode != 0 or not result.stdout.strip():
                return

            data = json.loads(result.stdout)
            if isinstance(data, dict):
                data = [data]

            for proc in data:
                pid = proc.get('Id', 0)

                # Only log processes we haven't seen yet
                if pid in self.seen_pids:
                    continue

                self.seen_pids.add(pid)

                name = proc.get('ProcessName', 'unknown')
                cpu = round(proc.get('CPU', 0) or 0, 1)
                mem = proc.get('MemMB', 0)

                message = f"Process: {name} (PID:{pid}) CPU:{cpu}s Mem:{mem}MB"

                # Flag high-resource processes
                severity = "INFO"
                if cpu > 60:
                    severity = "WARNING"
                if mem > 500:
                    severity = "WARNING"

                self.chain.add_log(
                    source=f"ProcessMonitor:{name}",
                    event_type="WIN_PROCESS",
                    message=message,
                    severity=severity
                )
                self.events_captured += 1

                # Only add a couple per cycle to keep it visible
                if self.events_captured % 5 == 0:
                    break

        except subprocess.TimeoutExpired:
            pass
        except Exception as e:
            pass

    def fetch_latest_log(self):
        """Legacy method — fetches one Application log (for backward compatibility)."""
        self._fetch_event_log("Application")

    def run_live_monitoring(self, duration_seconds=10, poll_interval=2):
        """Legacy CLI monitoring loop."""
        print(f"--- Listening for Real Windows Events ({duration_seconds}s) ---")
        start_time = time.time()

        while time.time() - start_time < duration_seconds:
            self._fetch_event_log("Application")
            self._fetch_event_log("System")
            self._fetch_running_processes()
            time.sleep(poll_interval)
