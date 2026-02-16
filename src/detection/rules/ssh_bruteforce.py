from src.detection.rules.base_rule import BaseRule


class SSHBruteForceRule(BaseRule):
    name = "Possible SSH Brute Force"
    severity = "HIGH"
    mitre_technique = "T1110"
    tactic = "Credential Access"

    def evaluate(self, events):
        failed = []

        for event in events:
            log = event.get("raw", "")

            if "Failed password" in log:
                failed.append(event)

        if len(failed) >= 3:
            return [{
                "rule_name": self.name,
                "severity": self.severity,
                "mitre_technique": self.mitre_technique,
                "tactic": self.tactic,
                "events": failed
            }]

        return []
