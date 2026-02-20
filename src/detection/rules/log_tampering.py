from .base_rule import BaseRule


class LogTamperingRule(BaseRule):

    def __init__(self):
        super().__init__(
            "LOG_TAMPERING",
            "Possible log tampering or indicator removal detected",
            "high",
            "T1070",
            "Defense Evasion"
        )

        self.suspicious_patterns = [
            "rm /var/log",
            "rm -rf /var/log",
            "truncate -s 0",
            "> /var/log",
            "echo '' > /var/log",
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
                        event=event,
                        confidence="high"
                    )
                    alerts.append(alert)

        return alerts