from collections import defaultdict
from datetime import timedelta
from src.detection.rules.base_rule import BaseRule


class SSHBruteForceRule(BaseRule):
    def __init__(self):
        super().__init__()
        self.rule_id = "SSH_BRUTE_FORCE"
        self.description = "Multiple SSH failed logins from same IP in short window"
        self.technique_id = "T1110"
        self.tactic = "Initial Access"
        self.severity = "medium"

    def evaluate(self, events):
        alerts = []
        failures_by_ip = defaultdict(list)

        for event in events:
            raw = event.get("raw")
            timestamp = event.get("timestamp")
            source_ip = event.get("source_ip")

            if not raw or not timestamp or not source_ip:
                continue

            if "Failed password" in raw:
                failures_by_ip[source_ip].append(timestamp)

        for ip, timestamps in failures_by_ip.items():
            timestamps.sort()
            window = []

            for ts in timestamps:
                window.append(ts)

                # keep only last 2 minutes
                window = [
                    t for t in window
                    if (ts - t).total_seconds() <= 120
                ]

                if len(window) >= 5:
                    alert = self.build_alert(
                        evidence=f"{len(window)} failures from {ip} in 2 minutes",
                        confidence="high"
                    )
                    alerts.append(alert)
                    break

        return alerts
