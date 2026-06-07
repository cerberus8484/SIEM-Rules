# VPN / Remote Access Pack

**20 rules — Splunk — impossible travel, Tor, ZTNA**

The VPN pack detects authentication anomalies in remote access infrastructure:
impossible travel, Tor exit node logins, concurrent sessions from different
geographies, and Zero Trust policy changes.

---

## Pack Summary

| Property | Value |
|---|---|
| Pack Directory | `vpn/` |
| ID Range | SP-770001 – SP-770020 |
| Platforms | Splunk |
| Rules | 20 |
| Key Sources | cisco:asa, paloalto:vpn, fortinet:vpn, zscaler:logs |
| MITRE Tactics | Initial Access, Lateral Movement |

---

## Rule Inventory

| Rule ID | Name | Severity | Confidence | Technique |
|---|---|---|---|---|
| SP-770001 | Impossible Travel (VPN Login) | HIGH | 85 | T1078 |
| SP-770002 | VPN Login from Tor Exit Node | CRITICAL | 95 | T1090.003 |
| SP-770003 | Concurrent VPN Sessions from Different Countries | HIGH | 82 | T1078 |
| SP-770004 | ZTNA Policy Downgraded to Permit All | CRITICAL | 92 | T1562 |
| SP-770005 | VPN Account Created Outside HR System | HIGH | 80 | T1136 |
| SP-770006 | SSL-VPN Exploit Pattern (Path Traversal) | CRITICAL | 90 | T1190 |
| SP-770007 | VPN Login at Unusual Hour (User Baseline) | MEDIUM | 68 | T1078 |
| SP-770008 | Split Tunnel Config Changed | HIGH | 78 | T1562 |
| SP-770009 | VPN Certificate Revocation Disabled | HIGH | 82 | T1553 |
| SP-770010 | RDP over VPN from Non-Corporate Asset | HIGH | 80 | T1021.001 |
| SP-770011 | VPN Session Duration Anomaly | MEDIUM | 65 | T1078 |
| SP-770012 | MFA Bypassed on VPN (Legacy Auth) | CRITICAL | 90 | T1556 |
| SP-770013 | VPN Log Forwarding Stopped | CRITICAL | 88 | T1562.008 |
| SP-770014 | Guest Network Access to Internal VPN | HIGH | 82 | T1021 |
| SP-770015 | VPN IP in Threat Intel Feed | HIGH | 80 | T1078 |
| SP-770016 | Always-On VPN Disabled by User | MEDIUM | 65 | T1562 |
| SP-770017 | Cloudflare Access Policy Set to Bypass | CRITICAL | 92 | T1562 |
| SP-770018 | VPN Password Spray (>50 failures) | HIGH | 85 | T1110.003 |
| SP-770019 | Unusual Protocol over VPN Tunnel | MEDIUM | 68 | T1571 |
| SP-770020 | VPN Admin Console Login from Untrusted IP | CRITICAL | 92 | T1078 |

---

## Test Fixtures

| Fixture | Type | Scenario |
|---|---|---|
| `tp_impossible_travel.json` | TRUE POSITIVE | Login from Germany at 08:00, then Miami at 09:15 — travel impossible |
| `fp_vpn_roaming.json` | FALSE POSITIVE | User with known travel schedule, same user agent |
