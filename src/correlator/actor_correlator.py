from collections import defaultdict


def correlate_by_source(events):
    """
    Groups events by source IP to build actor-based timelines.
    Returns dict:
    {
        "192.168.1.10": [event1, event2],
        "192.168.1.20": [event3]
    }
    """

    actors = defaultdict(list)

    for event in events:
        source_ip = event.get("source_ip")

        if source_ip:
            actors[source_ip].append(event)

    return dict(actors)
