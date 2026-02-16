from src.detection.rules.base_rule import BaseRule


class SuspiciousLoginAfterBruteForceRule(BaseRule):
    rule_id = "SSH_SUCCESS_AFTER_BRUTE_FORCE"
    description = "Successful SSH login after multiple failed attempts"
    technique_id = "T1078"
    tactic = "Initial Access"
    severity = "high"

    def evaluate(self, events):
        alerts = []
        failed_detected = False

        for event in events:
            raw = event.get("raw", "")

            if "Failed password" in raw:
                failed_detected = True

            if failed_detected and "Accepted password" in raw:
                alerts.append(
                    {
                        "rule_id": self.rule_id,
                        "description": self.description,
                        "technique_id": self.technique_id,
                        "tactic": self.tactic,
                        "severity": self.severity,
                    }
                )

        return alerts
