import argparse
import json
from src.correlation.attack_chain_engine import AttackChainEngine
from src.parser.log_parser import parse_log_file
from src.timeline.timeline_builder import build_timeline
from src.detection.rule_engine import RuleEngine
from src.detection.rule_registry import get_rules


def main():
    parser = argparse.ArgumentParser(description="Linux Attacker Timeline")
    parser.add_argument("--input", required=True, help="Path to log file")
    parser.add_argument("--json", action="store_true", help="Enable JSON output mode")

    args = parser.parse_args()

    print("INFO - Starting Linux Attacker Timeline pipeline")

    events = parse_log_file(args.input)

    rules = get_rules()
    engine = RuleEngine(rules)

    alerts = engine.detect(events)

    chain_engine = AttackChainEngine()
    incidents = chain_engine.correlate(alerts)

    if args.json:
        output = {
            "events_processed": len(events),
            "alerts_generated": len(alerts),
            "alerts": alerts,
            "incidents": incidents
        }
        print(json.dumps(output, default=str, indent=4))
    else:
        print("\n----- Correlated Incidents -----\n")
        for incident in incidents:
            print(incident)

        print("\n----- DETECTIONS -----\n")
        for alert in alerts:
            print(alert)

        print("\n----- ATTACK TIMELINE -----\n")
        timeline = build_timeline(events)
        for line in timeline:
            print(line)

        print("\n----- SUMMARY -----\n")
        print(f"Total Events Processed: {len(events)}")
        print(f"Total Alerts Generated: {len(alerts)}")
        print("INFO - Pipeline execution complete.")


if __name__ == "__main__":
    main()