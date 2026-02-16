from src.detection.rules.base_rule import BaseRule


class SSHBruteForceRule(BaseRule):
    rule_id = "SSH_BRUTE_FORCE"
    description = "Multiple failed SSH login attempts detected"
    technique_id = "T1110"
    tactic = "Credential Access"
    severity = "medium"

    def evaluate(self, events):
        alerts = []
        failed_count = 0

        for event in events:
            raw = event.get("raw", "")
            if "Failed password" in raw:
                failed_count += 1

        if failed_count >= 5:
            alerts.append(
                {
                    "rule_id": self.rule_id,
                    "description": self.description,
                    "technique_id": self.technique_id,
                    "tactic": self.tactic,
                    "severity": self.severity,
                    "count": failed_count,
                }
            )

        return alerts
