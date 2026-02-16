from datetime import datetime, timedelta


class CorrelationEngine:
    def __init__(self, alerts, window_minutes=10):
        self.alerts = alerts
        self.window = timedelta(minutes=window_minutes)

    def _within_window(self, alerts_subset):
        timestamps = []

        for alert in alerts_subset:
            ts = alert.get("timestamp")
            if ts:
                try:
    timestamps.append(datetime.fromisoformat(ts))
except ValueError:
    continue


        if len(timestamps) < 2:
            return False

        return max(timestamps) - min(timestamps) <= self.window

    def correlate(self):
        correlated = []
        rule_ids = {a.get("rule_id") for a in self.alerts}

        # Stage 1: Account takeover
        if (
            "SSH_BRUTE_FORCE" in rule_ids
            and "SUSPICIOUS_LOGIN_AFTER_BRUTEFORCE" in rule_ids
        ):
            subset = [
                a for a in self.alerts
                if a.get("rule_id") in (
                    "SSH_BRUTE_FORCE",
                    "SUSPICIOUS_LOGIN_AFTER_BRUTEFORCE",
                )
            ]

            if self._within_window(subset):
                correlated.append({
                    "rule_id": "ACCOUNT_TAKEOVER_CHAIN",
                    "description": "Brute force followed by login within time window",
                    "severity": "high",
                    "confidence": "high",
                    "tactic_chain": [
                        "Credential Access",
                        "Initial Access"
                    ],
                })

        # Stage 2: Privilege escalation
        if (
            any(a.get("rule_id") == "ACCOUNT_TAKEOVER_CHAIN" for a in correlated)
            and "SUDO_PRIVILEGE_ESCALATION" in rule_ids
        ):
            subset = [
                a for a in self.alerts
                if a.get("rule_id") in (
                    "SUDO_PRIVILEGE_ESCALATION",
                )
            ]

            if self._within_window(subset):
                correlated.append({
                    "rule_id": "FULL_SYSTEM_COMPROMISE",
                    "description": "Account takeover escalated to root within time window",
                    "severity": "critical",
                    "confidence": "high",
                    "tactic_chain": [
                        "Credential Access",
                        "Initial Access",
                        "Privilege Escalation"
                    ],
                })

        return correlated
