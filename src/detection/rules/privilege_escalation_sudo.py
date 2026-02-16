from src.detection.rules.base_rule import BaseRule


class SudoPrivilegeEscalationRule(BaseRule):
    rule_id = "SUDO_PRIVILEGE_ESCALATION"
    description = "User executed sudo command"
    technique_id = "T1548"
    tactic = "Privilege Escalation"
    severity = "medium"

    def evaluate(self, events):
        alerts = []

        for event in events:
            raw = event.get("raw", "")

            if "sudo" in raw and "COMMAND=" in raw:
                alerts.append(
                    {
                        "rule_id": self.rule_id,
                        "description": self.description,
                        "technique_id": self.technique_id,
                        "tactic": self.tactic,
                        "severity": self.severity,
                        "raw": raw,
                    }
                )

        return alerts
