# SOC Investigation: Possible TCP SYN Scan Burst

## Objective
Test a custom Suricata threshold rule against a packet capture from an
authorized Nmap scan of localhost.

## Scope
- Target: 127.0.0.1
- Capture: captures/port-scan.pcap
- IDS: Suricata 8.0.7
- Signature ID: 1000002

## Findings
- 24 packets captured; 1,560 bytes processed.
- Suricata generated one matching alert.
- Source IP: 127.0.0.1
- Destination IP and port: 127.0.0.1:53
- Alert verified in fast.log and eve.json.

## Assessment
The alert is consistent with the controlled local port-scan test.
It is a heuristic indicator, not proof of malicious activity. The
destination port shown is the packet that triggered the threshold;
it does not establish that port 53 was the primary target.

## Limitations
The rule counts matching SYN packets from one source over a time window.
It does not verify that each packet targets a distinct destination port
and may alert on legitimate connection bursts.

## Outcome
The custom rule generated an alert during offline PCAP analysis.
The result was verified in Suricata's text and JSON logs.
