# Real-Time Threat Simulation Engine


### Objective
Simulate real-time security log ingestion. Each event is processed immediately, classified, and assigned a dynamic risk score.

### Concepts
- Real-time event processing
- Streaming vs batch processing
- Event-driven architecture basics
- Dynamic risk scoring
- Security alert classification

### Streaming vs Batch
**Batch:** collects events and processes them together later.  
**Streaming:** processes each event as it arrives. This project simulates streaming with a short delay.

### Event-Driven Architecture
Each incoming security event triggers `process_event()`, which acts as the event handler.

### Risk Rules
- Failed login: +2
- Port scan: +4
- Malicious request: +5
- Repeated failed logins: +3
- Successful login after repeated failures: +3
- Repeated suspicious IP activity: +2
- Data download after suspicious login: +2

Severity:
- 0–2: LOW
- 3–4: MEDIUM
- 5–6: HIGH
- 7+: CRITICAL

### Files
- `realtime_threat_engine.py` – Python simulation
- `sample_events.json` – sample security events
- `live_processing_output.json` – generated results
- `live_output.log` – terminal processing output
- `README.md` – documentation
- `requirements.txt` – dependencies

### Run
```bash
python realtime_threat_engine.py
```

### Example
```text
[LIVE] Event #3 | ... | alice | login_failed | Risk=2 | LOW
       Alert: Failed login
```

### Note
This is an educational simulation. Production SOC environments typically use SIEMs, message queues/event brokers, stream processors, and distributed systems.
