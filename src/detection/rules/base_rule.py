class BaseRule:
    rule_id = ""
    description = ""
    technique_id = ""
    tactic = ""
    severity = "low"

    def evaluate(self, events):
        raise NotImplementedError

    def build_alert(self, evidence=None, confidence="medium"):
        return {
            "rule_id": self.rule_id,
            "description": self.description,
            "technique_id": self.technique_id,
            "tactic": self.tactic,
            "severity": self.severity,
            "confidence": confidence,
            "evidence": evidence or []
        }
