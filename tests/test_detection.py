from src.detection.rule_engine import RuleEngine
from src.detection.rule_registry import get_all_rules


def test_rule_engine_runs_without_crash():
    engine = RuleEngine(get_all_rules())

    sample_events = [
        {
            "timestamp": None,
            "raw": "Failed password for root from 192.168.1.10 port 22 ssh2"
        }
    ]

    alerts = engine.detect(sample_events)

    assert isinstance(alerts, list)
