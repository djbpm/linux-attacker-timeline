from src.detection.rules.base_rule import BaseRule

class ReverseShellRule(BaseRule):
    def __init__(self):
        super().__init__()
        self.rule_id = "REVERSE_SHELL"
        self.description = "Reverse shell execution detected"
        self.technique_id = "T1059"
        self.tactic = "Execution"
        self.severity = "high"

    def evaluate(self, events):
        alerts = []

        suspicious_patterns = [
            "/dev/tcp/",
            "nc -e",
            "bash -i",
            "0>&1",
            "socket.socket",
            "subprocess.call"
        ]

        for event in events:
            raw = event.get("raw", "")

            for pattern in suspicious_patterns:
                if pattern in raw:
                    alert = self.build_alert(
                        evidence=f"Reverse shell pattern detected: {pattern}",
                        confidence="high"
                    )
                    alerts.append(alert)
                    break

        return alerts
