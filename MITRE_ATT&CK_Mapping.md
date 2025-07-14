| Observation                                      | ATT&CK Tactic          | ATT&CK Technique Description                     |Technique ID      |
|--------------------------------------------------|------------------------|--------------------------------------------------|------------------|
| ZIP payload downloaded via HTTP                  | Ingress Tool Transfer  | Transfer tools or files over network             | T1105            |
| Phishing delivery via embedded link (URL)        | Initial Access         | Spearphishing Link                               | T1566.001        |
| Victim execution of downloaded ZIP               | Execution              | User Execution of malicious file                 | T1204.002        |
| DNS resolution of malicious domain               | Command and Control    | Application Layer Protocol: DNS                  | T1071.004        |
| HTTP GET used to retrieve dropper                | Command and Control    | Application Layer Protocol: Web Protocols        | T1071.001        |
| SMTP communication initiated                     | Command and Control    | Application Layer Protocol: Mail (SMTP)          | T1071.003        |
| STARTTLS upgrade observed in SMTP session        | Defense Evasion        | Obfuscated Files or Information                  | T1140            |
| Traffic evasion via encryption (TLS over SMTP)   | Command and Control    | Encrypted Channel                                | T1573.002        |
| C2 comms via public IPs / no domain resolution   | Defense Evasion        | Fallback Channel (IP-based)                      | T1008            |
| Response blocked by Spamhaus (521 5.7.1)         | Detection              | Abuse detection triggered                        | Not mapped*      |
| VirusTotal detection of payload                  | Discovery              | File and Artifact Analysis                       | T1083 (variant)  |
| TLS SNI reveals encrypted C2 domain              | Command and Control    | Application Layer Protocol: TLS (SNI)            | T1071.004        |
| JA3 TLS fingerprinting used to profile C2        | Defense Evasion        | Masquerading via network signature               | T1036.005        |
  
