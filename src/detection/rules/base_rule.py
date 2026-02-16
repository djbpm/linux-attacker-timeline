class BaseRule:
    rule_id = "BASE_RULE"
    description = "Base detection rule"
    technique_id = "N/A"
    tactic = "N/A"
    severity = "low"

    def evaluate(self, events):
        raise NotImplementedError("Rules must implement evaluate()")
