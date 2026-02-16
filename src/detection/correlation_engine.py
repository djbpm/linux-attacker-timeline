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

        # Stage 1: Account Takeover
        if (
            "SSH_BRUTE_FORCE" in rule_ids
            and "SUSPICIOUS_LOGIN_AFTER_BRUTEFORCE" in rule_ids
        ):
            subset = [
                a for a in self.alerts
                if a.get("rule_id") in {
                    "SSH_BRUTE_FORCE",
                    "SUSPICIOUS_LOGIN_AFTER_BRUTEFORCE"
                }
            ]

            if self._within_window(subset):
                correlated.append({
                    "rule_id": "ACCOUNT_TAKEOVER_CHAIN",
                    "severity": "high",
                    "confidence": "high",
                    "stage": "Account Takeover"
                })

        # Stage 2: Privilege Escalation
        if (
            "SUSPICIOUS_LOGIN_AFTER_BRUTEFORCE" in rule_ids
            and "PRIVILEGE_ESCALATION_SUDO" in rule_ids
        ):
            subset = [
                a for a in self.alerts
                if a.get("rule_id") in {
                    "SUSPICIOUS_LOGIN_AFTER_BRUTEFORCE",
                    "PRIVILEGE_ESCALATION_SUDO"
                }
            ]

            if self._within_window(subset):
                correlated.append({
                    "rule_id": "FULL_ATTACK_CHAIN",
                    "severity": "critical",
                    "confidence": "high",
                    "stage": "Privilege Escalation"
                })

        return correlated
