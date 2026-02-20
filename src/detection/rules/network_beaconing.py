from collections import defaultdict
import re
from src.detection.rules.base_rule import BaseRule


class NetworkBeaconingRule(BaseRule):
    def __init__(self):
        super().__init__(
            rule_id="NETWORK_BEACONING",
            description="Potential command-and-control beaconing detected",
            severity="high",
            technique_id="T1071",
            tactic="Command and Control"
        )

        self.threshold = 3

    def evaluate(self, events):
        ip_counter = defaultdict(int)
        pattern = re.compile(r"(?:nc|/dev/tcp|curl|wget).*?(\d{1,3}(?:\.\d{1,3}){3})")

        for event in events:
            raw = event.get("raw", "")
            match = pattern.search(raw)
            if match:
                ip = match.group(1)
                ip_counter[ip] += 1

        alerts = []

        for ip, count in ip_counter.items():
            if count >= self.threshold:
                alerts.append(
                    self.build_alert(
                        evidence=f"Repeated outbound connections to {ip} detected ({count} times)",
                        confidence="high" if count >= 5 else "medium"
                    )
                )

        return alerts