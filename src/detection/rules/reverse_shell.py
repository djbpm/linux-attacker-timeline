from .base_rule import BaseRule


class ReverseShellRule(BaseRule):

    def __init__(self):
        super().__init__(
            "REVERSE_SHELL",
            "Reverse shell execution detected",
            "high",
            "T1059",
            "Execution"
        )

    def evaluate(self, events):
        for e in events:
            if "/dev/tcp/" in e.get("raw", ""):
                return [{
                    "rule_id": self.rule_id,
                    "description": self.description,
                    "severity": self.severity,
                    "technique_id": self.technique_id,
                    "tactic": self.tactic,
                    "evidence": e.get("raw"),
                    "confidence": "high"
                }]
        return []
