def build_timeline(events):
    """
    Level 2 Timeline:
    - Sorts events chronologically
    """

    sorted_events = sorted(events, key=lambda e: e["timestamp"])
    return sorted_events
