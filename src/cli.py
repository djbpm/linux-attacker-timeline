import argparse

from src.normalizer.event_normalizer import normalize_lines
from src.correlator.event_correlator import correlate_events
from src.detection.rule_engine import detect_events
from src.timeline.timeline_builder import build_timeline
from src.output.formatter import print_detections, print_timeline
from src.intel.mitre_mapper import enrich_with_mitre


def main():
    parser = argparse.ArgumentParser(
        description="Linux Attacker Timeline Detection Engine"
    )

    parser.add_argument(
        "--input",
        required=True,
        help="Path to log file"
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Export alerts to JSON file"
    )

    args = parser.parse_args()
    
    print("DEBUG JSON FLAG:", args.json)


    # 1️⃣ Read file
    with open(args.input, "r") as f:
        lines = f.readlines()

    # 2️⃣ Normalize
    normalized_events = normalize_lines(lines)

    # 3️⃣ Correlate
    correlated_events = correlate_events(normalized_events)

    # 4️⃣ Detect
    detections = detect_events(correlated_events)

    # 5️⃣ MITRE Enrichment
    detections = enrich_with_mitre(detections)

    # 6️⃣ Optional JSON Export
    if args.json:
        from src.output.json_formatter import export_to_json
        export_to_json(detections)

    # 7️⃣ Build Timeline
    timeline = build_timeline(correlated_events)

    # 8️⃣ Output
    print_detections(detections)
    print_timeline(timeline)

    print("[INFO] Pipeline execution complete.")


if __name__ == "__main__":
    main()

