from .base_rule import BaseRule


class SudoPrivilegeEscalationRule(BaseRule):

    def __init__(self):
        super().__init__(
            "SUDO_PRIVILEGE_ESCALATION",
            "Suspicious sudo privilege escalation attempt",
            "high",
            "T1548",
            "Privilege Escalation"
        )

    def evaluate(self, events):
        for event in events:
            raw = event.get("raw", "")

            if "sudo:" in raw and "COMMAND=" in raw:
                return [
                    self.build_alert(
                        evidence=raw,
                        event=event,
                        confidence="high"
                    )
                ]

        return []