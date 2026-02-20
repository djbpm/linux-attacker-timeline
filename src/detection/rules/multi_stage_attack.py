from .base_rule import BaseRule


class MultiStageAttackRule(BaseRule):

    def __init__(self):
        super().__init__(
            "MULTI_STAGE_ATTACK",
            "Detected correlated multi-stage attack chain",
            "critical",
            "TA0001 + TA0004 + TA0003",
            "Multi-Stage Attack"
        )

    def evaluate(self, detections):

        rule_ids = [d.get("rule_id") for d in detections]

        required_chain = [
            "SSH_BRUTE_FORCE_SUCCESS",
            "SUDO_PRIVILEGE_ESCALATION",
            "REVERSE_SHELL",
            "NEW_USER_CREATION"
        ]

        if all(r in rule_ids for r in required_chain):
            return [{
                "rule_id": self.rule_id,
                "description": self.description,
                "severity": self.severity,
                "mitre_technique": self.technique_id,
                "tactic": self.tactic,
                "evidence": "Brute Force → Success → Priv Esc → Reverse Shell → Backdoor User",
                "confidence": "high"
            }]

        return []
