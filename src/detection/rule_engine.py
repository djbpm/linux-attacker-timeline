from src.detection.rule_registry import load_rules


class RuleEngine:
    def __init__(self):
        self.rules = load_rules()

    def validate_rule(self, rule):
        required_attributes = [
            "name",
            "severity",
            "mitre_technique",
            "tactic",
            "evaluate"
        ]

        for attr in required_attributes:
            if not hasattr(rule, attr):
                raise AttributeError(
                    f"Rule {rule.__class__.__name__} missing required attribute: {attr}"
                )

        if not callable(rule.evaluate):
            raise TypeError(
                f"Rule {rule.__class__.__name__}.evaluate must be callable"
            )

    def detect(self, events):
        alerts = []

        for rule in self.rules:
            self.validate_rule(rule)

            try:
                results = rule.evaluate(events)

                if results:
                    alerts.extend(results)

            except Exception as e:
                print(f"[ERROR] Rule {rule.__class__.__name__} failed: {e}")

        return alerts
