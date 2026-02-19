import re
from datetime import datetime


def normalize(raw_line):
    """
    Convert a single raw log line into a structured event dictionary.
    """

    event = {
        "timestamp": None,
        "source_ip": None,
        "raw": raw_line.strip()
    }

    # Extract timestamp (ISO format)
    timestamp_match = re.search(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", raw_line)
    if timestamp_match:
        try:
            event["timestamp"] = datetime.fromisoformat(timestamp_match.group())
        except ValueError:
            pass

    # Extract source IP
    ip_match = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", raw_line)
    if ip_match:
        event["source_ip"] = ip_match.group()

    return event


def normalize_events(raw_lines):
    """
    Convert list of raw lines into normalized event dictionaries.
    """
    return [normalize(line) for line in raw_lines]


