import json
import time
from datetime import datetime
from collections import defaultdict

class RealTimeThreatEngine:
    def __init__(self, risk_threshold=3):
        self.risk_threshold = risk_threshold
        self.failed_logins = defaultdict(int)
        self.ip_events = defaultdict(int)
        self.processed_events = 0
        self.event_scores = {
            "login_success": 0, "file_access": 0, "api_request": 0,
            "login_failed": 2, "port_scan": 4,
            "malicious_request": 5, "data_download": 1
        }

    def classify_event(self, event):
        score = self.event_scores.get(event["event_type"], 1)
        reasons = []
        user = event["user"]
        ip = event["ip"]
        event_type = event["event_type"]

        if event_type == "login_failed":
            self.failed_logins[user] += 1
            reasons.append("Failed login")
            if self.failed_logins[user] >= 3:
                score += 3
                reasons.append("Repeated failed logins")

        if event_type == "login_success" and self.failed_logins[user] >= 3:
            score += 3
            reasons.append("Successful login after repeated failures")

        self.ip_events[ip] += 1
        if self.ip_events[ip] >= 3 and event_type in {"port_scan","malicious_request","data_download"}:
            score += 2
            reasons.append("Repeated activity from same IP")

        if event_type == "data_download" and self.failed_logins[user] >= 3:
            score += 2
            reasons.append("Data access after suspicious login activity")

        if score >= 7:
            severity = "CRITICAL"
        elif score >= 5:
            severity = "HIGH"
        elif score >= self.risk_threshold:
            severity = "MEDIUM"
        else:
            severity = "LOW"
        return score, severity, reasons or ["No suspicious behavior detected"]

    def process_event(self, event):
        self.processed_events += 1
        score, severity, reasons = self.classify_event(event)
        result = {
            "processed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "event_number": self.processed_events,
            "event": event,
            "risk_score": score,
            "severity": severity,
            "reasons": reasons
        }
        print(f"[LIVE] Event #{self.processed_events} | {event['timestamp']} | "
              f"{event['user']} | {event['event_type']} | Risk={score} | {severity}")
        if reasons != ["No suspicious behavior detected"]:
            print("       Alert:", ", ".join(reasons))
        return result

    def run_stream(self, input_file, output_file="live_processing_output.json"):
        with open(input_file, "r") as file:
            events = json.load(file)
        results = []
        print("=" * 65)
        print("REAL-TIME THREAT SIMULATION ENGINE")
        print("Streaming events one at a time...")
        print("=" * 65)
        for event in events:
            results.append(self.process_event(event))
            time.sleep(0.2)
        with open(output_file, "w") as file:
            json.dump(results, file, indent=4)
        print("=" * 65)
        print(f"Processing complete. Events processed: {self.processed_events}")
        print(f"Output saved to: {output_file}")
        print("=" * 65)

def main():
    RealTimeThreatEngine().run_stream("sample_events.json")

if __name__ == "__main__":
    main()
