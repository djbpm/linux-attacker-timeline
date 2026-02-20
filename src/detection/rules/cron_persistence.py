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
            if "cron" in e.get("raw", "").lower():
                return [
                    self.build_alert(
                        evidence=e.get("raw"),
                        event=e,
                        confidence="medium"
                    )
                ]

        return []