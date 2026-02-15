import re
from datetime import datetime


def normalize_events(raw_logs):
    normalized = []

    for line in raw_logs:
        line = line.strip()

        if not line:
            continue

        # Extract timestamp (example: Feb 15 21:25:32)
        match = re.match(r"(\w+\s+\d+\s+\d+:\d+:\d+)", line)

        if match:
            timestamp_str = match.group(1)

            try:
                timestamp = datetime.strptime(timestamp_str, "%b %d %H:%M:%S")
            except ValueError:
                timestamp = None
        else:
            timestamp = None

        event = {
            "raw": line,
            "timestamp": timestamp,
            "correlation_key": extract_correlation_key(line)
        }

        normalized.append(event)

    return normalized


def extract_correlation_key(line):
    if "Failed password" in line:
        return "failed_login"
    elif "Accepted password" in line:
        return "successful_login"
    elif "wget" in line:
        return "download_command"
    elif "sudo" in line:
        return "privilege_escalation"
    else:
        return "unknown"

