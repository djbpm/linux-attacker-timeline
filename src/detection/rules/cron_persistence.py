from .base_rule import BaseRule


class CronPersistenceRule(BaseRule):

    def __init__(self):
        super().__init__(
            "CRON_PERSISTENCE",
            "Suspicious cron job persistence detected",
            "medium",
            "T1053",
            "Persistence"
        )

    def evaluate(self, events):
        for e in events:
            if "CRON" in e.get("raw", ""):
                return [{
                    "rule_id": self.rule_id,
                    "description": self.description,
                    "severity": self.severity,
                    "technique_id": self.technique_id,
                    "tactic": self.tactic,
                    "evidence": e.get("raw"),
                    "confidence": "medium"
                }]
        return []
