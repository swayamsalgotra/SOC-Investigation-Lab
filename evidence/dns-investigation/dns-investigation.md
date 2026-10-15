# DNS Detection Investigation

## 1. Objective
Validate a custom Suricata rule against a controlled DNS query captured
in a local lab, and preserve the resulting evidence.

## 2. Scope and Method
- Sensor: Suricata 8.0.7
- Input: captures/dns-query.pcap
- Detection rule SID: 1000003
- Query generated with: dig example.com
- Traffic protocol: UDP DNS

## 3. Observed Evidence
- Source: 10.0.2.15:33822
- DNS resolver: 192.168.1.1:53
- Query name: example.com
- Query type: A
- DNS response status: NOERROR
- Suricata matching alerts: 1
- Suricata alert action: allowed
- Suricata severity field: 3

The original capture contained a DNS request and a corresponding response.
The matching Suricata alert was verified in fast.log and eve.json.

## 4. Assessment
The custom rule successfully detected the DNS query for example.com.
This demonstrates basic DNS protocol inspection and custom-rule validation.

The observed activity was intentionally generated for this lab. The alert
does not establish malicious intent, command-and-control activity, or data
exfiltration. Severity 3 is the value reported by Suricata for this rule;
it is not an independent assessment of threat severity.

## 5. Limitations
- The rule matches a specific domain string and is not threat intelligence.
- A single DNS query is insufficient to establish malicious behavior.
- This was an offline PCAP analysis, not a live SOC monitoring test.
- No blocking or prevention action was demonstrated.

## 6. Outcome
PASS: the custom DNS rule generated one matching alert from the test PCAP.

## 7. Evidence
- dns-query.pcap
- local.rules
- fast.log
- eve.json
- SHA256SUMS
- DNS alert CSV and Python analyzer summary
