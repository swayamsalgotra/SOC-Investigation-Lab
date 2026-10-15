# HTTP User-Agent Negative Test

## Objective
Verify that the custom Suricata User-Agent rule does not
alert on an ordinary browser-style User-Agent.

## Test
- Destination: 127.0.0.1:8000
- User-Agent: Mozilla/5.0
- Rule under test: SID 1000004
- Analysis: Offline Suricata PCAP inspection

## Results
- PCAP captured: Yes
- Packets captured: 12
- Packets dropped by capture: 0
- SID 1000004 match: None observed

## Assessment
The test rule did not match the ordinary User-Agent in this
controlled test. This supports the expected behavior for
these test inputs, but does not establish the rule's overall
false-positive rate or detection effectiveness.

## Limitations
This was a single localhost request. Other rules and traffic
patterns require separate validation.

## Outcome
PASS if the EVE alert count is zero and the captured request
contains Mozilla/5.0.
