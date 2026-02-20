import argparse
import json
from src.parser.log_parser import parse_log_file
from src.detection.rule_registry import get_rules
from src.correlation.attack_chain_engine import AttackChainEngine


def main():

    parser = argparse.ArgumentParser(
        description="Linux Attacker Timeline Engine"
    )

    parser.add_argument(
        "--input",
        required=True,
        help="Path to input log file"
    )

    parser.add_argument(
        "--output",
        choices=["text", "json"],
        default="text",
        help="Output format (text or json)"
    )

    args = parser.parse_args()

    print("INFO - Starting Linux Attacker Timeline pipeline")

    # Parse log
    events = parse_log_file(args.input)

    # Load rules
    rules = get_rules()

    alerts = []
    for rule in rules:
        alerts.extend(rule.evaluate(events))

    # Correlation
    engine = AttackChainEngine()
    incidents = engine.correlate(alerts)

    # ----- OUTPUT SECTION -----
    if args.output == "json":

        output_data = {
            "alerts": alerts,
            "incidents": incidents,
            "summary": {
                "total_events": len(events),
                "total_alerts": len(alerts),
                "total_incidents": len(incidents)
            }
        }

        print(json.dumps(output_data, indent=4))

    else:

        print("\n----- Correlated Incidents -----\n")
        for incident in incidents:
            print(incident)

        print("\n----- DETECTIONS -----\n")
        for alert in alerts:
            print(alert)

        print("\n----- SUMMARY -----\n")
        print(f"Total Events Processed: {len(events)}")
        print(f"Total Alerts Generated: {len(alerts)}")
        print(f"Total Incidents Generated: {len(incidents)}")

        print("INFO - Pipeline execution complete.")


if __name__ == "__main__":
    main()