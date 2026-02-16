from datetime import datetime


def normalize_events(raw_lines):
    """
    Convert raw log lines into structured event dictionaries.
    """

    events = []

    for line in raw_lines:
        line = line.strip()
        if not line:
            continue

        event = {
            "timestamp": None,
            "raw": line,
        }

        # Try parsing standard SSH log format
        # Example:
        # Feb 15 21:25:32 server sshd[1234]: Failed password for root from 192.168.1.10 port 22 ssh2

        try:
            parts = line.split()
            month = parts[0]
            day = parts[1]
            time = parts[2]

            timestamp_str = f"{month} {day} {time}"
            timestamp = datetime.strptime(timestamp_str, "%b %d %H:%M:%S")

            event["timestamp"] = timestamp
        except Exception:
            # If parsing fails, keep raw only
            event["timestamp"] = None

        events.append(event)

    return events

