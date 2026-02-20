@'
from collections import defaultdict


class AttackChainEngine:
    def __init__(self):
        pass

    def correlate(self, alerts):
        if not alerts:
            return []

        normalized_alerts = []

        for alert in alerts:
            alert["timestamp"] = alert.get("timestamp", "")
            alert["host"] = alert.get("host", "unknown")
            normalized_alerts.append(alert)

        host_groups = defaultdict(list)

        for alert in normalized_alerts:
            host_groups[alert["host"]].append(alert)

        incidents = []

        for host, host_alerts in host_groups.items():
            sorted_alerts = sorted(
                host_alerts,
                key=lambda x: x.get("timestamp", "")
            )

            if len(sorted_alerts) > 1:
                incidents.append({
                    "host": host,
                    "alert_count": len(sorted_alerts),
                    "alerts": sorted_alerts
                })

        return incidents
'@ | Set-Content src\correlation\attack_chain_engine.py