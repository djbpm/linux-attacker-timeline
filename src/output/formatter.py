def print_detections(detections):
    print("\n===== DETECTIONS =====")

    if not detections:
        print("No security alerts detected.")
        return

    for detection in detections:
        print(f"\n[ALERT] {detection['rule_name']}")
        print(f"Severity: {detection['severity']}")

        mitre = detection.get("mitre", {})
        if mitre:
            print(f"MITRE Technique: {mitre.get('technique_id')} - {mitre.get('technique_name')}")
            print(f"Tactic: {mitre.get('tactic')}")

        if detection.get("frequency"):
            print(f"Frequency: {detection['frequency']}")

        print(f"Event: {detection['event']['raw']}")

def print_timeline(timeline):
    print("\n===== ATTACK TIMELINE =====")

    if not timeline:
        print("Timeline is empty.")
        return

    for event in timeline:
        timestamp_str = event["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp_str}] {event['raw']}")
