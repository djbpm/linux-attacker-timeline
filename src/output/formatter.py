def print_detections(detections):
    print("===== DETECTIONS =====")

    if not detections:
        print("No security alerts detected.")
        return

    for detection in detections:
        rule_name = detection.get("rule_name", "Unknown Rule")
        severity = detection.get("severity", "Unknown")
        raw_event = detection.get("event", {}).get("raw", "No raw event")

        print(f"\n[ALERT] {rule_name}")
        print(f"Severity: {severity}")
        print(f"Event: {raw_event}")


def print_timeline(timeline):
    print("\n===== ATTACK TIMELINE =====")

    if not timeline:
        print("No events available.")
        return

    for item in timeline:
        timestamp = item.get("timestamp", "N/A")
        raw = item.get("raw", "No raw event")
        print(f"[{timestamp}] {raw}")

