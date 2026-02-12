from pathlib import Path


def collect_lines(file_path: str):
    """
    Reads a log file and returns raw lines.
    """
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {file_path}")

    with path.open("r", encoding="utf-8", errors="ignore") as f:
        return f.readlines()
