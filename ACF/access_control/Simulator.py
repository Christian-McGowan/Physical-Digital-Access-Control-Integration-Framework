import csv
import os
import random
from datetime import datetime, timedelta
from typing import Dict, Any

class Simulator:
    """
    Simulates physical and digital access events based on a configuration.
    """
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.users = config['users']
        self.physical_zones = config['physical_zones']
        self.digital_resources = config['digital_resources']
        
        self.log_dir = "logs"
        self.log_file_path = os.path.join(self.log_dir, "event_log.csv")
        
        self._prepare_logging()

    def _prepare_logging(self):
        """Ensures log directory exists and clears the old log file."""
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)
        if os.path.exists(self.log_file_path):
            os.remove(self.log_file_path)

    def _log_event(self, event_time: datetime, event_type: str, user_id: str, target_id: str, status: str, details: str):
        """Writes a single event to the CSV log file."""
        file_exists = os.path.isfile(self.log_file_path)
        with open(self.log_file_path, 'a', newline='') as csvfile:
            fieldnames = ["timestamp", "event_type", "user_id", "user_name", "target_id", "status", "details"]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            if not file_exists:
                writer.writeheader()
            
            writer.writerow({
                "timestamp": event_time.isoformat(),
                "event_type": event_type,
                "user_id": user_id,
                "user_name": self.users.get(user_id, {}).get("name", "Unknown"),
                "target_id": target_id,
                "status": status,
                "details": details
            })

    def attempt_physical_access(self, user_id: str, zone_id: str, event_time: datetime):
        """Simulates a physical access attempt."""
        user = self.users.get(user_id)
        zone = self.physical_zones.get(zone_id)
        
        if not user or not zone:
            self._log_event(event_time, "PHYSICAL", user_id, zone_id, "FAILURE", "Invalid user or zone.")
            return

        if user["access_level"] >= zone["required_level"]:
            self._log_event(event_time, "PHYSICAL", user_id, zone_id, "SUCCESS", f"Access granted to {zone['name']}.")
        else:
            self._log_event(event_time, "PHYSICAL", user_id, zone_id, "FAILURE", f"Insufficient privilege for {zone['name']}.")

    def attempt_digital_access(self, user_id: str, resource_id: str, source_ip: str, event_time: datetime):
        """Simulates a digital resource access attempt."""
        user = self.users.get(user_id)
        resource = self.digital_resources.get(resource_id)
        
        if not user or not resource:
            self._log_event(event_time, "DIGITAL", user_id, resource_id, "FAILURE", "Invalid user or resource.")
            return

        if user["ip_address"] != source_ip:
            self._log_event(event_time, "DIGITAL", user_id, resource_id, "FAILURE", f"Access from untrusted IP: {source_ip}.")
            return
            
        if user["access_level"] >= resource["required_level"]:
            self._log_event(event_time, "DIGITAL", user_id, resource_id, "SUCCESS", f"Access granted to {resource['name']}.")
        else:
            self._log_event(event_time, "DIGITAL", user_id, resource_id, "FAILURE", f"Insufficient privilege for {resource['name']}.")

    def run_full_simulation(self):
        """Runs a comprehensive set of scenarios to generate rich log data."""
        base_time = datetime.now()

        # 1. Normal day-to-day operations
        self.attempt_physical_access("user001", "zone_lobby", base_time + timedelta(seconds=1))
        self.attempt_digital_access("user002", "resource_fileshare", "192.168.1.12", base_time + timedelta(seconds=5))

        # 2. Insufficient privilege denials
        self.attempt_physical_access("user003", "zone_datacenter", base_time + timedelta(seconds=10))
        self.attempt_digital_access("user001", "resource_domain_controller", "192.168.1.10", base_time + timedelta(seconds=15))

        # 3. Impossible Travel Scenario
        self.attempt_physical_access("user002", "zone_office", base_time + timedelta(minutes=1))
        self.attempt_digital_access("user002", "resource_fileshare", "203.0.113.55", base_time + timedelta(minutes=2)) # Foreign IP

        # 4. Brute-Force Scenario
        for i in range(5):
            self.attempt_physical_access("user003", "zone_datacenter", base_time + timedelta(minutes=3, seconds=i*10))

        # 5. Anomalous Access Hours Scenario
        off_hours_time = base_time.replace(hour=3, minute=15)
        self.attempt_digital_access("admin01", "resource_domain_controller", "192.168.1.2", off_hours_time)

        # 6. Privilege Escalation Probing Scenario
        self.attempt_digital_access("user002", "resource_payroll", "192.168.1.12", base_time + timedelta(minutes=5)) # Level 2 trying for Level 3
        self.attempt_physical_access("user002", "zone_datacenter", base_time + timedelta(minutes=6)) # Level 2 trying for Level 4