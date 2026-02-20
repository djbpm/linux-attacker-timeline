from .base_rule import BaseRule


class SensitiveFileAccessRule(BaseRule):

    def __init__(self):
        super().__init__(
            "SENSITIVE_FILE_ACCESS",
            "Sensitive file access detected",
            "medium",
            "T1005",
            "Collection"
        )

    def evaluate(self, events):
        sensitive_files = ["/etc/shadow", "/etc/passwd"]

        for e in events:
            raw = e.get("raw", "")
            if any(f in raw for f in sensitive_files):
                return [{
                    "rule_id": self.rule_id,
                    "description": self.description,
                    "severity": self.severity,
                    "technique_id": self.technique_id,
                    "tactic": self.tactic,
                    "evidence": raw,
                    "confidence": "medium"
                }]
        return []
