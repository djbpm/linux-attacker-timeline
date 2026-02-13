def correlate_events(events):
    frequency_map = {}

    # First pass: assign correlation keys + count
    for event in events:
        raw = event.get("raw", "").lower()

        if "failed login" in raw:
            key = "failed_login"
        elif "wget" in raw or "curl" in raw:
            key = "download_command"
        else:
            key = raw

        event["correlation_key"] = key
        frequency_map[key] = frequency_map.get(key, 0) + 1

    # Second pass: attach frequency
    for event in events:
        key = event.get("correlation_key")
        event["frequency"] = frequency_map.get(key, 1)

    return events
