import csv
from datetime import datetime, timedelta
from typing import List, Dict, Any

class LogAnalyzer:
    """Analyzes event logs for various suspicious activities."""
    
    def __init__(self, log_file_path: str):
        self.log_file_path = log_file_path
        try:
            with open(self.log_file_path, 'r') as f:
                self.logs = list(csv.DictReader(f))
        except FileNotFoundError:
            print(f"Error: Log file not found at '{self.log_file_path}'.")
            self.logs = []

    def generate_report(self):
        """Generates and prints a full security analysis report."""
        if not self.logs:
            print("Log file is empty or could not be read. Cannot generate report.")
            return

        print("\n--- Security Analysis Report ---")
        
        detections = {
            "Impossible Travel": self._detect_impossible_travel(),
            "Brute-Force Attempts": self._detect_brute_force(),
            "Anomalous Access Hours": self._detect_anomalous_hours(),
            "Privilege Escalation Probing": self._detect_privilege_escalation_probing()
        }
        
        total_alerts = 0
        for category, alerts in detections.items():
            if alerts:
                total_alerts += len(alerts)
                print(f"\n[!] {category} Detected:")
                for alert in alerts:
                    print(f"  - {alert}")
        
        if total_alerts == 0:
            print("\n[*] No major suspicious activities detected.")
            
        print("\n--- End of Report ---")

    def _detect_impossible_travel(self) -> List[str]:
        alerts = []
        user_events: Dict[str, Any] = {}
        for event in self.logs:
            if event["event_type"] == "PHYSICAL" and event["status"] == "SUCCESS":
                user_events[event["user_id"]] = {"timestamp": datetime.fromisoformat(event["timestamp"])}
            elif "untrusted IP" in event["details"]:
                user_id = event["user_id"]
                if user_id in user_events:
                    time_diff = datetime.fromisoformat(event["timestamp"]) - user_events[user_id]["timestamp"]
                    if time_diff < timedelta(hours=1):
                        alerts.append(f"User '{user_id}' had successful on-site access followed by a remote attempt {time_diff} later.")
        return alerts

    def _detect_brute_force(self) -> List[str]:
        alerts = []
        failed_attempts: Dict[str, List[datetime]] = {}
        for event in self.logs:
            if event["status"] == "FAILURE":
                key = f"{event['user_id']}@{event['target_id']}"
                timestamp = datetime.fromisoformat(event["timestamp"])
                if key not in failed_attempts:
                    failed_attempts[key] = []
                failed_attempts[key].append(timestamp)
                
                # Prune old attempts
                window_start = timestamp - timedelta(minutes=5)
                failed_attempts[key] = [t for t in failed_attempts[key] if t > window_start]
                
                if len(failed_attempts[key]) >= 5:
                    alerts.append(f"User '{event['user_id']}' on target '{event['target_id']}'. {len(failed_attempts[key])} failures in 5 minutes.")
                    failed_attempts[key] = [] # Clear to prevent re-alerting
        return alerts

    def _detect_anomalous_hours(self, start_hour: int = 22, end_hour: int = 6) -> List[str]:
        alerts = []
        for event in self.logs:
            timestamp = datetime.fromisoformat(event["timestamp"])
            if (timestamp.hour >= start_hour or timestamp.hour < end_hour) and event['status'] == 'SUCCESS':
                 alerts.append(f"Successful access by '{event['user_name']}' to '{event['target_id']}' at an unusual time: {timestamp.time()}.")
        return alerts

    def _detect_privilege_escalation_probing(self) -> List[str]:
        alerts = []
        probing_attempts: Dict[str, int] = {}
        for event in self.logs:
            if event["status"] == "FAILURE" and "Insufficient privilege" in event["details"]:
                user_id = event["user_id"]
                probing_attempts[user_id] = probing_attempts.get(user_id, 0) + 1
        
        for user_id, count in probing_attempts.items():
            if count > 1:
                alerts.append(f"User '{user_id}' made {count} failed attempts against resources above their privilege level, suggesting probing.")
        return alerts