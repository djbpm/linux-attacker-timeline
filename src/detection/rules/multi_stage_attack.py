from src.detection.rules.base_rule import BaseRule


class MultiStageAttackRule(BaseRule):

    def __init__(self):
        super().__init__()
        self.rule_id = "MULTI_STAGE_ATTACK"
        self.severity = "critical"
        self.mitre_technique = "TA0001 + TA0004 + TA0003"
        self.tactic = "Multi-Stage Attack"

    def evaluate(self, events):
        indicators = {
            "bruteforce": False,
            "success": False,
            "sudo": False,
            "reverse_shell": False,
            "new_user": False,
        }

        for event in events:
            raw = event.get("raw", "")

            if "Failed password" in raw:
                indicators["bruteforce"] = True

            if "Accepted password" in raw:
                indicators["success"] = True

            if "sudo:" in raw:
                indicators["sudo"] = True

            if "/dev/tcp/" in raw:
                indicators["reverse_shell"] = True

            if "new user:" in raw:
                indicators["new_user"] = True

        if all(indicators.values()):
            return [{
                "rule_id": self.rule_id,
                "severity": self.severity,
                "mitre_technique": self.mitre_technique,
                "tactic": self.tactic,
                "evidence": "Brute Force → Success → Priv Esc → Reverse Shell → Backdoor User",
                "confidence": "high"
            }]

        return []
