import json

def export_to_json(detections, filename="detections.json"):
    with open(filename, "w") as f:
        json.dump(detections, f, indent=4)

    print(f"[INFO] JSON exported to {filename}")
