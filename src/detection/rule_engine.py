from src.detection.rule_registry import get_all_rules


class RuleEngine:
    def __init__(self, rules=None):
        # Allow dependency injection for testing
        self.rules = rules if rules is not None else get_all_rules()

    def validate_rule(self, rule):
        if not hasattr(rule, "evaluate"):
            raise TypeError(
                f"Rule {rule.__class__.__name__} must implement evaluate()"
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
