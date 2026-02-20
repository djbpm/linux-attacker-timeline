class AttackChainEngine:

    def __init__(self):
        pass

    def correlate(self, alerts):
        if not alerts:
            return []

        TACTIC_ORDER = [
            "Initial Access",
            "Execution",
            "Privilege Escalation",
            "Persistence",
            "Defense Evasion",
            "Command and Control",
            "Collection"
        ]

        # Group alerts by host
        hosts = {}
        for alert in alerts:
            host = alert.get("host", "unknown")
            hosts.setdefault(host, []).append(alert)

        incidents = []

        for host, host_alerts in hosts.items():

            # Sort by timestamp
            host_alerts.sort(key=lambda x: x.get("timestamp", ""))

            # Extract unique tactics in appearance order
            progression = []
            for alert in host_alerts:
                tactic = alert.get("tactic")
                if tactic and tactic not in progression:
                    progression.append(tactic)

            # Convert tactics to index order
            order_indices = [
                TACTIC_ORDER.index(t)
                for t in progression
                if t in TACTIC_ORDER
            ]

            is_progressive = order_indices == sorted(order_indices)
            unique_tactics = len(progression)

            if unique_tactics >= 4 and is_progressive:
                confidence = "high"
                severity = "critical"
            elif unique_tactics >= 3:
                confidence = "medium"
                severity = "high"
            else:
                confidence = "low"
                severity = "medium"

            if unique_tactics >= 2:
                incidents.append({
                    "host": host,
                    "attack_progression": progression,
                    "total_alerts": len(host_alerts),
                    "confidence": confidence,
                    "severity": severity
                })

        return incidents
