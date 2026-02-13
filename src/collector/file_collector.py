def collect_lines(file_path: str):
    """
    Reads a log file and returns all lines.
    """
    lines = []

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                lines.append(line.strip())
    except FileNotFoundError:
        print(f"[ERROR] File not found: {file_path}")
        return []

    return lines
