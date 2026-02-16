class CorrelationEngine:
    def __init__(self, alerts):
        self.alerts = alerts

    def correlate(self):
        correlated = []

        rule_ids = {a.get("rule_id") for a in self.alerts}

        # Account takeover chain
        if (
            "SSH_BRUTE_FORCE" in rule_ids
            and "SUSPICIOUS_LOGIN_AFTER_BRUTEFORCE" in rule_ids
        ):
            correlated.append({
                "rule_id": "ACCOUNT_TAKEOVER_CHAIN",
                "description": "Brute force followed by successful login",
                "severity": "high",
                "confidence": "high",
                "tactic_chain": [
                    "Credential Access",
                    "Initial Access"
                ],
            })

        # Privilege escalation chain
        if (
            "ACCOUNT_TAKEOVER_CHAIN" in {a.get("rule_id") for a in correlated}
            and "SUDO_PRIVILEGE_ESCALATION" in rule_ids
        ):
            correlated.append({
                "rule_id": "FULL_SYSTEM_COMPROMISE",
                "description": "Compromised account escalated privileges",
                "severity": "critical",
                "confidence": "high",
                "tactic_chain": [
                    "Credential Access",
                    "Initial Access",
                    "Privilege Escalation"
                ],
            })

        return correlated
