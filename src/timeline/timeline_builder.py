def build_timeline(events):
    """
    Builds a sorted timeline from parsed events.
    Handles both dict events and raw string events safely.
    """

    structured_events = []

    for event in events:
        # If event is already structured
        if isinstance(event, dict):
            structured_events.append(event)

        # If event is raw string, convert it
        elif isinstance(event, str):
            structured_events.append({
                "timestamp": event.split(" ")[0],
                "raw": event
            })

    # Sort safely by timestamp
    structured_events.sort(key=lambda x: x.get("timestamp", ""))

    return structured_events
