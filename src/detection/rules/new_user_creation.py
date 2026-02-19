from src.detection.rules.base_rule import BaseRule


class NewUserCreationRule(BaseRule):

    def __init__(self):
        super().__init__()
        self.rule_id = "NEW_USER_CREATION"
        self.description = "New system user account created (possible persistence)"
        self.technique_id = "T1136"
        self.tactic = "Persistence"
        self.severity = "high"

    def evaluate(self, events):
        alerts = []

        for event in events:
            raw = event.get("raw", "")

            if (
                "useradd" in raw.lower()
                or "adduser" in raw.lower()
                or "new user:" in raw.lower()
            ):
                alert = self.build_alert(
                    evidence=f"New user creation detected: {raw}",
                    confidence="high"
                )
                alerts.append(alert)

        return alerts
