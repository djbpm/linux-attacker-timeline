import json
from typing import List, Dict


def export_to_json(alerts: List[Dict], output_file: str = "output.json") -> None:
    """
    Export detection alerts to a JSON file.
    """
    with open(output_file, "w") as f:
        json.dump(alerts, f, indent=4)

    print(f"[INFO] JSON export written to {output_file}")
