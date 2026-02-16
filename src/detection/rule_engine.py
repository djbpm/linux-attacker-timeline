from src.detection.rule_registry import get_all_rules
from src.detection.correlation_engine import CorrelationEngine


class RuleEngine:
    def __init__(self, rules=None):
        self.rules = rules if rules is not None else get_all_rules()

    # Backward compatible public API
    def detect(self, events):
        return self.run(events)

    # Internal execution pipeline
    def run(self, events):
        alerts = []

        for rule in self.rules:
            alerts.extend(rule.evaluate(events))

        # Correlation phase
        correlator = CorrelationEngine(alerts)
        correlated_alerts = correlator.correlate()

        alerts.extend(correlated_alerts)

        return alerts
