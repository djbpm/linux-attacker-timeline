from .base_rule import BaseRule

class SudoPrivilegeEscalationRule(BaseRule):
    rule_id = "SUDO_PRIVILEGE_ESCALATION"
    description = "Suspicious sudo privilege escalation activity detected"
    technique_id = "T1548"
    tactic = "Privilege Escalation"
    severity = "high"

    def evaluate(self, events):
        alerts = []
        sudo_events = []

        for event in events:
            raw = event.get("raw", "")

            if "sudo" in raw and ("COMMAND=" in raw or "session opened" in raw):
                sudo_events.append(raw)

        if sudo_events:
            alerts.append(
                self.build_alert(
                    evidence={
                        "sudo_event_count": len(sudo_events),
                        "events": sudo_events[:5]  # limit output size
                    },
                    confidence="high" if len(sudo_events) > 3 else "medium"
                )
            )

        return alerts
