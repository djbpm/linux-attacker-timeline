from src.detection.rules.base_rule import BaseRule


class SSHBruteForceRule(BaseRule):
    rule_id = "SSH_BRUTE_FORCE"
    description = "Multiple failed SSH login attempts detected"
    technique_id = "T1110"
    tactic = "Credential Access"
    severity = "medium"

    def evaluate(self, events):
        alerts = []
        failed_events = []

        for event in events:
            raw = event.get("raw", "")
            if "Failed password" in raw:
                failed_events.append(raw)

        if len(failed_events) >= 5:
            alerts.append(
                self.build_alert(
                    evidence=failed_events[:5],
                    confidence="high" if len(failed_events) > 10 else "medium"
                )
            )

        return alerts
