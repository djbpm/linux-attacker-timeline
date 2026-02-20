from collections import defaultdict
from datetime import datetime


TACTIC_ORDER = [
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Collection",
    "Command and Control",
    "Exfiltration"
]


class AttackChainEngine:
    def __init__(self):
        self.tactic_order = TACTIC_ORDER

    def group_by_host(self, alerts):
        grouped = defaultdict(list)
        for alert in alerts:
            host = alert.get("host", "unknown_host")
            grouped[host].append(alert)
        return grouped

    def tactic_index(self, tactic):
        if tactic not in self.tactic_order:
            return -1
        return self.tactic_order.index(tactic)

    def build_progressive_chain(self, alerts):
        # Remove alerts without valid timestamp
        valid_alerts = [
            a for a in alerts
            if a.get("timestamp") is not None
        ]

        if not valid_alerts:
            return []

        sorted_alerts = sorted(
            valid_alerts,
            key=lambda x: x["timestamp"]
        )

        chain = []
        last_index = -1

        for alert in sorted_alerts:
            tactic = alert.get("tactic")
            current_index = self.tactic_index(tactic)

            if current_index > last_index:
                chain.append(alert)
                last_index = current_index

        return chain

    def calculate_severity(self, stage_count):
        if stage_count >= 6:
            return "CRITICAL"
        elif stage_count >= 4:
            return "HIGH"
        elif stage_count >= 2:
            return "MEDIUM"
        return "LOW"

    def aggregate_confidence(self, chain):
        if not chain:
            return 0.0
        total = sum(a.get("confidence", 0) for a in chain)
        return round(total / len(chain), 2)

    def correlate(self, alerts):
        incidents = []

        grouped_alerts = self.group_by_host(alerts)

        for host, host_alerts in grouped_alerts.items():
            chain = self.build_progressive_chain(host_alerts)

            if len(chain) < 2:
                continue

            incident = {
                "incident_id": f"INC-{host}-{int(datetime.now().timestamp())}",
                "host": host,
                "stage_count": len(chain),
                "severity": self.calculate_severity(len(chain)),
                "confidence": self.aggregate_confidence(chain),
                "attack_chain": [
                    {
                        "tactic": a.get("tactic"),
                        "technique_id": a.get("technique_id"),
                        "rule_id": a.get("rule_id"),
                        "timestamp": a.get("timestamp")
                    }
                    for a in chain
                ]
            }

            incidents.append(incident)

        return incidents