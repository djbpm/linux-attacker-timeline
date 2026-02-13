MITRE_MAPPING = {
    "R001": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access"
    },
    "R002": {
        "technique_id": "T1105",
        "technique_name": "Ingress Tool Transfer",
        "tactic": "Command and Control"
    },
    "R003": {
        "technique_id": "T1110 + T1105",
        "technique_name": "Brute Force + Ingress Tool Transfer",
        "tactic": "Credential Access + Command and Control"
    }
}


def enrich_with_mitre(detections):
    for detection in detections:
        rule_id = detection.get("rule_id")

        if rule_id in MITRE_MAPPING:
            detection["mitre"] = MITRE_MAPPING[rule_id]

    return detections
