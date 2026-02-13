from datetime import datetime
import re

def normalize_lines(lines):
    """
    Level 2 Normalizer:
    - Extracts timestamp if present
    - Falls back to ingestion time
    - Returns structured event objects
    """

    normalized_events = []

    timestamp_pattern = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"

    for line in lines:
        line = line.strip()

        # Try to extract ISO timestamp from log line
        match = re.search(timestamp_pattern, line)

        if match:
            try:
                parsed_timestamp = datetime.fromisoformat(match.group())
            except:
                parsed_timestamp = datetime.utcnow()
        else:
            parsed_timestamp = datetime.utcnow()

        event = {
            "timestamp": parsed_timestamp,
            "raw": line,
            "event_type": "generic"
        }

        normalized_events.append(event)

    return normalized_events
