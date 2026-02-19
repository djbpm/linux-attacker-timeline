from src.detection.rules.base_rule import BaseRule


class SudoPrivilegeEscalationRule(BaseRule):

    def __init__(self):
        super().__init__()
        self.rule_id = "SUDO_PRIVILEGE_ESCALATION"
        self.description = "Suspicious sudo privilege escalation attempt"
        self.technique_id = "T1548"
        self.tactic = "Privilege Escalation"
        self.severity = "high"

    def evaluate(self, events):
        alerts = []

        for event in events:
            raw = event.get("raw", "")

            if not raw:
                continue

            if "sudo" in raw and ("sudo su" in raw or "sudo -i" in raw or "COMMAND=" in raw):
                alert = self.build_alert(
                    evidence=f"Sudo privilege escalation detected: {raw}",
                    confidence="high"
                )
                alerts.append(alert)

        return alerts
