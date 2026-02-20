from src.detection.rules.base_rule import BaseRule


class LogTamperingRule(BaseRule):
    def __init__(self):
        super().__init__(
            rule_id="LOG_TAMPERING",
            description="Possible log tampering or indicator removal detected",
            severity="high",
            technique_id="T1070",
            tactic="Defense Evasion"
        )

        self.suspicious_patterns = [
            "rm /var/log",
            "rm -rf /var/log",
            "truncate -s 0",
            "> /var/log",
            "echo \"\" > /var/log",
            "sed -i",
            "journalctl --vacuum",
            "history -c",
            "unset HISTFILE"
        ]

    def evaluate(self, events):
        alerts = []

        for event in events:
            raw = event.get("raw", "").lower()

            for pattern in self.suspicious_patterns:
                if pattern in raw:
                    alert = self.build_alert(
                        evidence=f"Log tampering pattern detected: {pattern}",
                        confidence="high"
                    )
                    alerts.append(alert)

        return alerts
