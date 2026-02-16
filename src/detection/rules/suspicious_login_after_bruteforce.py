from src.detection.rules.base_rule import BaseRule


class SuspiciousLoginAfterBruteForceRule(BaseRule):
    name = "Successful Login After Multiple Failures"
    severity = "CRITICAL"
    mitre_technique = "T1078"
    tactic = "Persistence"

    def evaluate(self, events):
        failed_count = 0
        success_event = None

        for event in events:
            log = event.get("raw", "")

            if "Failed password" in log:
                failed_count += 1

            if "Accepted password" in log:
                success_event = event

        if failed_count >= 3 and success_event:
            return [{
                "rule_name": self.name,
                "severity": self.severity,
                "mitre_technique": self.mitre_technique,
                "tactic": self.tactic,
                "events": [success_event]
            }]

        return []
