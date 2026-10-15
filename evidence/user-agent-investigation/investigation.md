# HTTP User-Agent Detection Investigation

## Objective
Validate a custom Suricata rule against a controlled HTTP request.

## Environment
- Suricata: 8.0.7
- Traffic: Local HTTP on 127.0.0.1:8000
- Capture: captures/user-agent-test.pcap
- Rule SID: 1000004

## Observations
- User-Agent: SOC-LAB-SuspiciousClient
- Source: 127.0.0.1:41042
- Destination: 127.0.0.1:8000
- Packets captured: 12
- Packets dropped by capture: 0
- Matching Suricata alert: Confirmed
- Suricata priority: 3

## Assessment
The custom rule matched the test User-Agent in the captured
HTTP request. The matching alert was verified in fast.log and
eve.json.

This was controlled localhost traffic. The User-Agent string
is a lab indicator and does not independently establish
malicious behavior.

## Limitations
- The test used a single controlled request.
- The rule matches a specific string and is not threat
  intelligence by itself.
- The test used offline PCAP analysis, not live SOC monitoring.
- No blocking or prevention was tested.

## Outcome
PASS — controlled detection test succeeded.

## Evidence
- user-agent-test.pcap
- local.rules
- fast.log
- eve.json
