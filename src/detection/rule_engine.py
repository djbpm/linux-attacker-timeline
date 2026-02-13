def detect_events(events):
    detections = []

    failed_login_count = 0
    suspicious_download_detected = False

    # First pass — analyze
    for event in events:
        correlation_key = event.get("correlation_key", "")
        frequency = event.get("frequency", 1)

        # Count brute force attempts (aggregated)
        if correlation_key == "failed_login":
            failed_login_count = frequency

        # Detect suspicious download
        if correlation_key == "download_command":
            suspicious_download_detected = True
            detections.append({
                "rule_id": "R002",
                "rule_name": "Suspicious Download Command",
                "severity": "high",
                "frequency": frequency,
                "mitre": {
                    "technique_id": "T1105",
                    "technique_name": "Ingress Tool Transfer",
                    "tactic": "Command and Control"
                },
                "event": event
            })

    # Rule 1 — Brute Force (only once)
    if failed_login_count >= 3:
        detections.append({
            "rule_id": "R001",
            "rule_name": "Brute Force Login Attempt",
            "severity": "high",
            "frequency": failed_login_count,
            "mitre": {
                "technique_id": "T1110",
                "technique_name": "Brute Force",
                "tactic": "Credential Access"
            },
            "event": {
                "raw": f"{failed_login_count} failed login attempts detected"
            }
        })

    # Rule 3 — Multi-Stage
    if failed_login_count >= 3 and suspicious_download_detected:
        detections.append({
            "rule_id": "R003",
            "rule_name": "Multi-Stage Attack Pattern",
            "severity": "critical",
            "frequency": None,
            "mitre": {
                "technique_id": "T1110 + T1105",
                "technique_name": "Brute Force + Ingress Tool Transfer",
                "tactic": "Credential Access + Command and Control"
            },
            "event": {
                "raw": "Multiple failed logins followed by suspicious download activity"
            }
        })

    return detections
