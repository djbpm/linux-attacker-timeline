from collections import defaultdict
import re
from .base_rule import BaseRule


class NetworkBeaconingRule(BaseRule):

    def __init__(self):
        super().__init__(
            "NETWORK_BEACONING",
            "Potential command-and-control beaconing detected",
            "high",
            "T1071",
            "Command and Control"
        )

        self.threshold = 3

    def evaluate(self, events):
        ip_counter = defaultdict(int)
        ip_event_reference = {}

        pattern = re.compile(r"(?:nc|/dev/tcp|curl|wget).*?(\d{1,3}(?:\.\d{1,3}){3})")

        for event in events:
            raw = event.get("raw", "")
            match = pattern.search(raw)

            if match:
                ip = match.group(1)
                ip_counter[ip] += 1

                # store first event reference for this IP
                if ip not in ip_event_reference:
                    ip_event_reference[ip] = event

        alerts = []

        for ip, count in ip_counter.items():
            if count >= self.threshold:
                reference_event = ip_event_reference[ip]

                alerts.append(
                    self.build_alert(
                        evidence=f"Repeated outbound connections to {ip} detected ({count} times)",
                        event=reference_event,
                        confidence="high" if count >= 5 else "medium"
                    )
                )

        return alerts