import argparse

from src.normalizer.event_normalizer import normalize_lines
from src.correlator.event_correlator import correlate_events
from src.detection.rule_engine import detect_events
from src.timeline.timeline_builder import build_timeline
from src.output.formatter import print_detections, print_timeline
from src.intel.mitre_mapper import enrich_with_mitre


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Path to log file")
    args = parser.parse_args()

    # 1. Read file
    with open(args.input, "r") as f:
        lines = f.readlines()

    # 2. Normalize
    normalized_events = normalize_lines(lines)

    # 3. Correlate
    correlated_events = correlate_events(normalized_events)

    # 4. Detect
    detections = detect_events(correlated_events)

    # 5. MITRE Enrichment
    detections = enrich_with_mitre(detections)

    # 6. Build timeline
    timeline = build_timeline(correlated_events)

    # 7. Output
    print_detections(detections)
    print_timeline(timeline)

    print("[INFO] Pipeline execution complete.")


if __name__ == "__main__":
    main()
