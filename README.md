# KIU full infrastructure compromise

Internal network penetration test and incident response writeup for a fictional university, Karam International University (KIU). Built as the Capstone project for Cyber Nashama Bootcamp 12 (Camp 12), run by the National Cyber Security Center Jordan (NCSC) with Al Hussein Technical University.

The engagement is an assumed-breach test: an attacker with a foothold on the internal network and no credentials. Starting from there, all three servers were compromised, every database was accessed, and root was obtained on the main web server. The repo also covers the defensive side: how the attack was detected and reconstructed from logs, and how each finding was fixed and re-tested.

Assessment dates 20–21 October 2026. Report version 1.0 Final.

> **Lab use only.** Everything here was run against virtual machines on an isolated lab network (192.168.40.0/24). KIU is fictional. The report is marked confidential because it contains working exploit detail and lab credentials. Do not use these techniques against systems you are not authorized to test.

## Environment

| Host | IP | OS | Role | Key software |
|---|---|---|---|---|
| Server 1 (`target`) | 192.168.40.133 | Ubuntu 20.04 | Learning management | Chamilo LMS 1.11.24, Adminer 4.7.8 |
| Server 2 (`glpi-victim`) | 192.168.40.139 | Ubuntu 22.04 | IT helpdesk and webmail | GLPI 10.0.2, Roundcube 1.5.0, Postfix, Dovecot, MariaDB |
| Server 3 (`redis`) | 192.168.40.140 | Ubuntu 20.04 | Public website, cache, database | GravCMS 1.7.0, Redis 5.0.7, MariaDB 10.3 |
| SIEM | 192.168.40.129 | | Log aggregation and detection | Splunk Enterprise (forwarders on all three servers) |
| Attacker | 192.168.40.130 | Kali Linux | Operator host | |

Domains: lms.kiu.edu.jo (.133), helpdesk.kiu.edu.jo (.139), kiu.edu.jo (.140).

## Findings

Twelve findings: 4 Critical, 4 High, 4 Medium. CVSS values are assessed for this environment, not vendor-published scores.

| ID | Finding | CVE | Severity | Server |
|---|---|---|---|---|
| F-01 | GLPI code injection to RCE (`htmLawedTest.php`) | CVE-2022-35914 | Critical | .139 |
| F-02 | GravCMS unauthenticated scheduler RCE | CVE-2021-21425 | Critical | .140 |
| F-03 | Redis Lua sandbox escape to RCE | CVE-2022-0543 | Critical | .140 |
| F-04 | Redis unauthenticated access, sensitive data exposure | | Critical | .140 |
| F-05 | Chamilo unrestricted file upload to RCE (`bigUpload`) | CVE-2023-4220 | High | .133 |
| F-06 | Adminer server-side request forgery | CVE-2021-21311 | High | .133 |
| F-07 | MariaDB exposed to the network | | High | .140 |
| F-08 | Plaintext credentials in database and Redis | | High | .140 |
| F-09 | Roundcube stored XSS | CVE-2023-43770 | Medium | .139 |
| F-10 | GLPI `htmLawedTest.php` test file left in production | | Medium | .139 |
| F-11 | SMTP VRFY enabled, user enumeration | | Medium | .139 |
| F-12 | GravCMS admin panel and debug mode exposed | | Medium | .140 |

F-06 (Adminer SSRF) and F-09 (Roundcube XSS) were confirmed by version identification but not exploited during the engagement.

## Attack path

Reconnaissance on 20 October mapped three hosts, their services, and their web directories, and turned up Redis on port 6379 with no authentication. Exploitation ran on 21 October.

1. **GLPI (.139), initial access.** CVE-2022-35914 in the bundled `htmLawedTest.php` gave an unauthenticated `www-data` shell. Post-exploitation dumped the GLPI database (asset inventory and user password hashes), which identified .140 as the main web server.
2. **GravCMS (.140), root.** CVE-2021-21425 writes arbitrary YAML to the scheduler endpoint using a nonce lifted from the exposed admin panel. The scheduler cron runs as root, so the injected job returned a root shell with no privilege-escalation step. An SSH key was then planted in `/root/.ssh/authorized_keys` for persistence.
3. **Credential pivot.** Unauthenticated Redis (F-04) held the database password, an LMS admin JWT, and the application secret in cleartext. That password opened `university_db`, whose `system_config` table stored cleartext credentials for every service.
4. **Redis (.140), second RCE.** CVE-2022-0543 (Lua sandbox escape) gave an independent code-execution path on the same server, separate from the scheduler route.
5. **Chamilo (.133).** CVE-2023-4220 in the `bigUpload` endpoint uploaded a PHP webshell with no authentication, giving a `www-data` shell and access to student and faculty accounts.

The single cause running through all of it: known CVEs with public exploit code, exposed management interfaces and test files, cleartext credentials tying the servers together, and a flat network with no segmentation.

## Detection and incident response

The defensive phase treats the monitoring as KIU's existing setup, then works the incident from the alert rather than from prior knowledge of the attack.

Monitoring in place: Splunk Enterprise as the SIEM with forwarders on all three servers; Suricata IDS running the Emerging Threats ruleset plus two custom scan-detection rules; auditd with custom execution and file-watch rules; and file integrity monitoring on the web roots, `/tmp`, cron directories and SSH key paths.

The trigger was a Suricata alert in Splunk, `ET SCAN Possible Nmap User-Agent`, from a host absent from the asset inventory. From there the analyst pivoted through Apache access logs, auditd execution keys (`priv_exec`, `wwwdata_exec`), the MySQL general log, Postfix mail logs and Suricata flow records to rebuild the full chain from scan to persistence. The report ties every stage to MITRE ATT&CK, maps the defensive controls to MITRE D3FEND, and lists the indicators of compromise (attacker IP, reverse-shell ports 4444/5555/6666, exploit URL paths, dropped files).

The Splunk manager went offline partway through the investigation, so the evidence in the report comes from host-side logs that kept writing locally. The main lesson recorded: host-level logging (auditd, Apache, Postfix, MySQL) carried the investigation when the SIEM dashboard was unavailable.

The report is honest about what the monitoring missed. Documented detection gaps include no alert on the Nmap host-discovery sweep or the gobuster 404 flood, Redis client commands not logged at default level, and the SIEM outage itself.

## Remediation

Every finding was fixed on its server, preferring the vendor's own approach over blunt blocks. Highlights:

- GLPI: deleted `htmLawedTest.php`, blocked `/vendor` in Apache
- GravCMS: removed the malicious scheduler job, restricted `/admin` to the local subnet
- Redis: bound to 127.0.0.1, set `requirepass`
- MariaDB: bound to 127.0.0.1
- Chamilo: applied the upstream security fix (removed the `postUnsupported()` upload path, matching commit `3b487a5` / 1.11.26), removed the webshell
- Adminer: upgraded 4.7.8 to 4.8.1, added an IP restriction
- Postfix: disabled the VRFY command

All six exploitable attack paths were re-run from the Kali host after remediation and confirmed blocked (403, connection refused, or the vulnerable function removed).

## Repository layout

```
.
├── README.md
├── report/
│   └── Karam-Alhmoud_project_CC12.pdf   # full 77-page report: pentest + incident response
└── images/                             # screenshots, if published separately
```

The single report covers three parts: system architecture, the red team engagement with all 12 findings, and the incident response writeup (timeline, ATT&CK and D3FEND mapping, remediation, replication proof).

## Walkthrough videos

Each CVE PoC and the defensive phase has a recorded walkthrough of five minutes or less.

<!-- Add YouTube (unlisted) links here, one per video -->

## Author

Karam Al-Hmoud, eJPT. Cybersecurity graduate of Jordan University of Science and Technology and intern at NCSCJO.

[LinkedIn](https://www.linkedin.com/in/karamalhmoud) · [GitHub](https://github.com/karam-03)
