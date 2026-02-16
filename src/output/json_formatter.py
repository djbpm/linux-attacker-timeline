import json
from datetime import datetime


def default_serializer(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()
    return str(obj)


def export_json(file_path, detections, timeline):
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "detections": detections,
                "timeline": timeline
            },
            f,
            indent=4,
            default=default_serializer
        )
