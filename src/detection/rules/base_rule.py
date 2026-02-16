class BaseRule:
    rule_id = "BASE"
    rule_name = "Base Rule"
    severity = "LOW"

    def run(self, events):
        raise NotImplementedError("Rule must implement run()")
