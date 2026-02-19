import argparse
from src.parser.log_parser import parse_log_file
from src.timeline.timeline_builder import build_timeline
from src.detection.rule_engine import RuleEngine
from src.detection.rule_registry import get_rules


def main():
    parser = argparse.ArgumentParser(description="Linux Attacker Timeline")
    parser.add_argument("--input", required=True, help="Path to log file")
    args = parser.parse_args()

    print("INFO - Starting Linux Attacker Timeline pipeline")

    events = parse_log_file(args.input)

    rules = get_rules()
    engine = RuleEngine(rules)

    alerts = engine.detect(events)

    print("\n===== DETECTIONS =====\n")
    for alert in alerts:
        print(alert)

    print("\n===== ATTACK TIMELINE =====\n")
    timeline = build_timeline(events)
    for line in timeline:
        print(line)

    print("\n===== SUMMARY =====\n")
    print(f"Total Events Processed: {len(events)}")
    print(f"Total Alerts Generated: {len(alerts)}")
    print("INFO - Pipeline execution complete.")


if __name__ == "__main__":
    main()
