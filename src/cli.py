import argparse
import logging

from src.normalizer.event_normalizer import normalize_events
from src.correlator.correlator import correlate_events
from src.detection.rule_engine import detect_events
from src.timeline.timeline_builder import build_timeline
from src.output.formatter import print_detections, print_timeline
<<<<<<< HEAD
from src.intel.mitre_mapper import enrich_with_mitre
=======
>>>>>>> fdd4fa6 (Add CI pipeline with GitHub Actions)
from src.output.json_formatter import export_to_json


def main():
    # -------------------------
    # Logging Configuration
    # -------------------------
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )

    logger = logging.getLogger(__name__)
    logger.info("Starting Linux Attacker Timeline pipeline")

    # -------------------------
    # CLI Arguments
    # -------------------------
    parser = argparse.ArgumentParser()
<<<<<<< HEAD

    parser.add_argument(
        "--input",
        required=True,
        help="Path to log file"
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Export detections to JSON file"
    )

    args = parser.parse_args()

    # 1. Read file
    with open(args.input, "r", encoding="utf-8") as f:
        lines = f.readlines()
=======
    parser.add_argument("--input", required=True, help="Path to log file")
    parser.add_argument("--json", action="store_true", help="Export alerts to JSON file")
    args = parser.parse_args()

    # -------------------------
    # 1. Load logs
    # -------------------------
    logger.info("Loading log file")
    with open(args.input, "r") as f:
        raw_logs = f.readlines()
>>>>>>> fdd4fa6 (Add CI pipeline with GitHub Actions)

    # -------------------------
    # 2. Normalize
    # -------------------------
    logger.info("Normalizing events")
    normalized_events = normalize_events(raw_logs)

    # -------------------------
    # 3. Correlate
    # -------------------------
    logger.info("Correlating events")
    correlated_events = correlate_events(normalized_events)

    # -------------------------
    # 4. Detect
    # -------------------------
    logger.info("Running detection engine")
    detections = detect_events(correlated_events)

<<<<<<< HEAD
    # 5. MITRE Enrichment
    detections = enrich_with_mitre(detections)

    # 6. Optional JSON export
    if args.json:
        export_to_json(detections)

    # 7. Build timeline
    timeline = build_timeline(correlated_events)

    # 8. Output to console
=======
    # -------------------------
    # 5. Build Timeline
    # -------------------------
    logger.info("Building timeline")
    timeline = build_timeline(correlated_events)

    # -------------------------
    # 6. Output
    # -------------------------
>>>>>>> fdd4fa6 (Add CI pipeline with GitHub Actions)
    print_detections(detections)
    print_timeline(timeline)

    if args.json:
        logger.info("Exporting detections to JSON")
        export_to_json(detections)
        logger.info("JSON exported successfully")

    logger.info("Pipeline execution complete.")


if __name__ == "__main__":
    main()

<<<<<<< HEAD

=======
>>>>>>> fdd4fa6 (Add CI pipeline with GitHub Actions)
