import json
 HEAD


def export_to_json(detections, filename="detections.json"):
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(detections, f, indent=4)

from datetime import datetime


def convert_datetime(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()
    return str(obj)


def export_to_json(detections, filename="detections.json"):
    with open(filename, "w") as f:
        json.dump(
            detections,
            f,
            indent=4,
            default=convert_datetime
        )
 fdd4fa6 (Add CI pipeline with GitHub Actions)

    print(f"[INFO] JSON exported to {filename}")
