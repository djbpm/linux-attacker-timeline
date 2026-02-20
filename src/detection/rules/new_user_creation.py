from .base_rule import BaseRule


class NewUserCreationRule(BaseRule):

    def __init__(self):
        super().__init__(
            "NEW_USER_CREATION",
            "New system user account created",
            "high",
            "T1136",
            "Persistence"
        )

    def evaluate(self, events):
        for e in events:
            if "useradd" in e.get("raw", ""):
                return [{
                    "rule_id": self.rule_id,
                    "description": self.description,
                    "severity": self.severity,
                    "technique_id": self.technique_id,
                    "tactic": self.tactic,
                    "evidence": e.get("raw"),
                    "confidence": "high"
                }]
        return []
