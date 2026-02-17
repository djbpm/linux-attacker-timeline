from dataclasses import dataclass
from typing import Optional, Dict, Any
from datetime import datetime


@dataclass
class TimelineEvent:
    timestamp: datetime
    source: str              # auth.log, bash_history, cron, etc.
    event_type: str          # ssh_login, sudo, cron_modification, etc.
    description: str
    user: Optional[str] = None
    host: Optional[str] = None
    severity: str = "low"
    raw: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "event_type": self.event_type,
            "description": self.description,
            "user": self.user,
            "host": self.host,
            "severity": self.severity,
            "raw": self.raw,
        }
