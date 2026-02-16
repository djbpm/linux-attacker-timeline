def correlate_events(events):
    """
    Adds simple frequency counting to events.
    Groups events by correlation_key.
    """

    frequency_map = {}

    for event in events:
        key = event.get("correlation_key")

        if key not in frequency_map:
            frequency_map[key] = 0

        frequency_map[key] += 1

    correlated = []

    for event in events:
        key = event.get("correlation_key")

        event_copy = event.copy()
        event_copy["frequency"] = frequency_map.get(key, 1)

        correlated.append(event_copy)

    return correlated
