import argparse
from src.collector.file_collector import collect_lines
def main():
    parser = argparse.ArgumentParser(
        description="Linux Attacker Timeline - Host-level reconstruction tool"
    )

    parser.add_argument(
        "--input",
        help="Path to input log file",
        required=False
    )

    args = parser.parse_args()

    print("Linux Attacker Timeline - v0.1")

    if args.input:
        print(f"Processing log file: {args.input}")
    else:
        print("No input file provided.")


if __name__ == "__main__":
    main()
