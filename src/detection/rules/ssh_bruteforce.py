from .base_rule import BaseRule


class SSHBruteForceRule(BaseRule):

    def __init__(self):
        super().__init__(
            "SSH_BRUTE_FORCE",
            "Multiple SSH failed login attempts detected",
            "medium",
            "T1110",
            "Credential Access"
        )

    def evaluate(self, events):
        failed = [e for e in events if "Failed password" in e.get("raw", "")]
        if len(failed) >= 5:
            return [{
                "rule_id": self.rule_id,
                "description": self.description,
                "severity": self.severity,
                "technique_id": self.technique_id,
                "tactic": self.tactic,
                "evidence": f"{len(failed)} failed SSH attempts detected",
                "confidence": "high"
            }]
        return []
