def build_timeline(events):
    """
    Build a sorted attack timeline from correlated events.
    """

    if not events:
        return []

    # Sort safely (avoid KeyError)
    sorted_events = sorted(
        events,
        key=lambda e: e.get("timestamp", "")
    )

    timeline = []

    for event in sorted_events:
        timeline.append({
            "timestamp": event.get("timestamp", "N/A"),
            "raw": event.get("raw", "No raw event")
        })

    return timeline
