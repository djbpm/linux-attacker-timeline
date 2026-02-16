def print_detections(detections):
    if not detections:
        print("No detections found.")
        return

    for alert in detections:
        print(f"[ALERT] {alert.get('rule_name', 'Unknown')}")
        print(f"Severity: {alert.get('severity')}")
        print(f"MITRE Technique: {alert.get('mitre_technique')}")
        print(f"Tactic: {alert.get('tactic')}")

        for event in alert.get("events", []):
            if isinstance(event, dict) and "raw" in event:
                print(f"Event: {event['raw']}")
            else:
                print(f"Event: {event}")

        print()


def print_timeline(timeline):
    for event in timeline:
        if isinstance(event, dict) and "raw" in event:
            print(event["raw"])
        else:
            print(event)


def print_summary(total_events, total_alerts):
    print(f"Total Events Processed: {total_events}")
    print(f"Total Alerts Generated: {total_alerts}")
