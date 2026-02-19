def parse_log_file(file_path):
    events = []

    with open(file_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            parts = line.split(" ", 1)
            if len(parts) < 2:
                continue

            timestamp = parts[0]
            raw = parts[1]

            event = {
                "timestamp": timestamp,
                "raw": raw
            }

            events.append(event)

    return events

