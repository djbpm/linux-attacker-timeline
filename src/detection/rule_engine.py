class RuleEngine:
    def __init__(self, rules):
        self.rules = rules

    def detect(self, events):
        alerts = []

        for rule in self.rules:
            try:
                result = rule.evaluate(events)
                if result:
                    alerts.extend(result)
            except Exception as e:
                print(f"[ERROR] Rule {rule.__class__.__name__} failed: {e}")

        return alerts
