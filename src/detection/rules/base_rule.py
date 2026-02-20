class BaseRule:
    def __init__(self, rule_id, description, severity, technique_id, tactic):
        self.rule_id = rule_id
        self.description = description
        self.severity = severity
        self.technique_id = technique_id
        self.tactic = tactic

    def build_alert(self, evidence, event=None, confidence="high"):
        return {
            "rule_id": self.rule_id,
            "description": self.description,
            "severity": self.severity,
            "technique_id": self.technique_id,
            "tactic": self.tactic,
            "evidence": evidence,
            "confidence": confidence,
            "timestamp": event.get("timestamp", "") if event else "",
            "host": event.get("host", "unknown") if event else "unknown"
        }