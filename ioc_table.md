| Type        | Value                                | Description                                  | Threat Level | ATT&CK ID     |
|-------------|----------------------------------------|--------------------------------------------|--------------|---------------|
| URL         | /wp-content/L/?160244                 | Suspicious ZIP payload download path        | High         | T1105         |
| Domain      | mtp.evotek.vn                         | Resolved to payload IP                      | High         | T1566.001     |
| IP Address  | 101.99.3.20                           | Hosted Emotet payload + C2 endpoint         | High         | T1071.001     |
| File Hash   | 701c6abc5d4f1fafe912f494b4e72cfa       | Payload file hash (ZIP)                    | High         | T1204.002     |
| Protocol    | HTTP                                  | Used to deliver malicious ZIP               | High         | T1071.001     |
| Port        | 25                                    | SMTP used for C2/spambot traffic            | High         | T1071.003     |
| Domain      | mail.sim23.ua                         | Target of SMTP C2 connection                | High         | T1585.002     |
| IP Address  | 195.128.226.50                        | Likely mail server for C2                   | Medium       | T1071.003     |
| IP Address  | 173.66.46.97                          | SMTP server rejected by Spamhaus            | Medium       | T1008         |
| User-Agent  | Microsoft-CryptoAPI/10.0              | Used in HTTP GET for payload                | Medium       | T1043         |
| SNI         | midcoastsupplies.com.au               | TLS Server Name Indication (C2 domain)      | High         | T1071.004     |
| JA3         | 37cdab6ff1bd1c195bacb776c5213bf2       | JA3 TLS fingerprint of C2 traffic          | High         | T1036.005     |

