from src.detection.rules.base_rule import BaseRule


class SSHBruteForceSuccessRule(BaseRule):
    def __init__(self):
        super().__init__()
        self.rule_id = "SSH_BRUTE_FORCE_SUCCESS"
        self.description = "Successful login after multiple SSH failures"
        self.technique_id = "T1078"
        self.tactic = "Initial Access"
        self.severity = "high"

    def evaluate(self, events):
        alerts = []

        failed_attempts = []
        success_event = None

        for event in events:
            raw = event.get("raw", "")

            if "Failed password" in raw:
                failed_attempts.append(event)

            if "Accepted password" in raw:
                success_event = event

        if success_event and len(failed_attempts) >= 5:
            alerts.append(
                self.build_alert(
                    evidence=f"Successful login after {len(failed_attempts)} failures",
                    confidence="high"
                )
            )

        return alerts

