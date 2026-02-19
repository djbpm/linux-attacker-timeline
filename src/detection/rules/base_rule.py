class BaseRule:
    def __init__(self):
        self.rule_id = "BASE_RULE"
        self.description = ""
        self.technique_id = None
        self.tactic = None
        self.severity = "low"

    def build_alert(self, evidence, confidence):
        return {
            "rule_id": self.rule_id,
            "description": self.description,
            "severity": self.severity,
            "technique_id": self.technique_id,
            "tactic": self.tactic,
            "evidence": evidence,
            "confidence": confidence
        }
