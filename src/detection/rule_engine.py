def detect_events(events):
    detections = []

    for event in events:
        raw = event.get("raw", "").lower()
        freq = event.get("frequency", 1)
        key = event.get("correlation_key", "")

        # R001 - SSH Brute Force
        if key == "failed_login" and freq >= 3:
            detections.append({
                "rule_id": "R001",
                "rule_name": "Possible SSH Brute Force",
                "severity": "HIGH",
                "event": event
            })

        # R002 - Malicious Download
        if key == "download_command" and "wget" in raw:
            detections.append({
                "rule_id": "R002",
                "rule_name": "Suspicious File Download",
                "severity": "MEDIUM",
                "event": event
            })

    # R003 - Multi-stage Attack
    has_bruteforce = any(
        e.get("correlation_key") == "failed_login" and e.get("frequency", 1) >= 3
        for e in events
    )

    has_download = any(
        e.get("correlation_key") == "download_command"
        for e in events
    )

    if has_bruteforce and has_download:
        detections.append({
            "rule_id": "R003",
            "rule_name": "Multi-Stage Intrusion Pattern",
            "severity": "CRITICAL",
            "event": {"raw": "Multi-stage attack detected"}
        })

    return detections


