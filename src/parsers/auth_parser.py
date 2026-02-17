import re
from datetime import datetime
from typing import List
from src.core.event import TimelineEvent


AUTH_REGEX = {
    "failed_ssh": re.compile(r"Failed password for (invalid user )?(?P<user>\w+)"),
    "accepted_ssh": re.compile(r"Accepted password for (?P<user>\w+)"),
    "sudo": re.compile(r"sudo: (?P<user>\w+)"),
    "user_add": re.compile(r"useradd\[(\d+)\]: new user: name=(?P<user>\w+)"),
}


def parse_auth_log(lines: List[str]) -> List[TimelineEvent]:
    events = []

    for line in lines:
        timestamp = extract_timestamp(line)
        if not timestamp:
            continue

        for event_type, pattern in AUTH_REGEX.items():
            match = pattern.search(line)
            if match:
                events.append(
                    TimelineEvent(
                        timestamp=timestamp,
                        source="auth.log",
                        event_type=event_type,
                        description=line.strip(),
                        user=match.groupdict().get("user"),
                        severity="medium" if event_type == "failed_ssh" else "low",
                        raw={"line": line.strip()},
                    )
                )

    return events


def extract_timestamp(line: str):
    try:
        return datetime.strptime(line[:15], "%b %d %H:%M:%S")
    except Exception:
        return None
