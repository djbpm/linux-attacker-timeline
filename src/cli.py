import argparse
import logging
import sys

from src.collector.file_collector import collect_file
from src.normalizer.event_normalizer import normalize_events
from src.correlator.event_correlator import correlate_events
from src.detection.rule_engine import RuleEngine
from src.timeline.timeline_builder import build_timeline
from src.output.formatter import print_detections, print_timeline, print_summary
from src.output.json_formatter import export_json


def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )


def parse_arguments():
    parser = argparse.ArgumentParser(description="Linux Attacker Timeline Engine")

    parser.add_argument("--input", required=True, help="Path to log file")
    parser.add_argument("--severity", required=False, help="Filter by severity")
    parser.add_argument("--export", required=False, help="Export detections to JSON")

    return parser.parse_args()


def main():
    args = parse_arguments()

    logging.info("Starting Linux Attacker Timeline pipeline")

    raw_events = collect_file(args.input)
    normalized = normalize_events(raw_events)
    correlated = correlate_events(normalized)

    engine = RuleEngine()
    detections = engine.detect(correlated)

    if args.severity:
        detections = [
            d for d in detections
            if d.get("severity") == args.severity
        ]

    timeline = build_timeline(correlated)

    print("\n===== DETECTIONS =====\n")
    print_detections(detections)

    print("\n===== ATTACK TIMELINE =====\n")
    print_timeline(timeline)

    print("\n===== SUMMARY =====\n")
    print_summary(len(correlated), len(detections))

    if args.export:
        export_json(detections, args.export)
        logging.info(f"Detections exported to {args.export}")

    logging.info("Pipeline execution complete.")


if __name__ == "__main__":
    try:
        setup_logging()
        main()
    except Exception:
        logging.exception("Fatal error occurred")
        sys.exit(1)
