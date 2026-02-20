from .base_rule import BaseRule


class SSHBruteForceSuccessRule(BaseRule):

    def __init__(self):
        super().__init__(
            "SSH_BRUTE_FORCE_SUCCESS",
            "Successful login after multiple SSH failures",
            "high",
            "T1078",
            "Initial Access"
        )

    def evaluate(self, events):
        failed = [e for e in events if "Failed password" in e.get("raw", "")]
        success = [e for e in events if "Accepted password" in e.get("raw", "")]

        if len(failed) >= 5 and len(success) >= 1:
            return [{
                "rule_id": self.rule_id,
                "description": self.description,
                "severity": self.severity,
                "technique_id": self.technique_id,
                "tactic": self.tactic,
                "evidence": "Successful login after multiple failures",
                "confidence": "high"
            }]

        return []
