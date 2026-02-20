def parse_log_file(file_path):
    events = []

    with open(file_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            parts = line.split(" ", 2)
            if len(parts) < 3:
                continue

            timestamp = parts[0]
            host = parts[1]
            raw = parts[2]

            event = {
                "timestamp": timestamp,
                "host": host,
                "raw": raw
            }

            events.append(event)

    return events