# Threat Intelligence Feeds & Indicator Sources Research

> Comprehensive catalog of publicly available threat intelligence feeds for forensic triage tool integration.
> Research date: 2026-03-22

---

## Table of Contents

1. [abuse.ch Ecosystem](#1-abusech-ecosystem)
2. [AlienVault OTX / LevelBlue](#2-alienvault-otx--levelblue)
3. [MITRE ATT&CK](#3-mitre-attck)
4. [VirusTotal](#4-virustotal)
5. [Phishing Feeds](#5-phishing-feeds)
6. [IP/Domain Reputation Feeds](#6-ipdomain-reputation-feeds)
7. [Hash-Based IOC Feeds](#7-hash-based-ioc-feeds)
8. [C2/Botnet/Ransomware Trackers](#8-c2botnetransomware-trackers)
9. [Government CERT Feeds](#9-government-cert-feeds)
10. [Tor Exit Node Lists](#10-tor-exit-node-lists)
11. [MISP Ecosystem](#11-misp-ecosystem)
12. [Additional Free/Community Feeds](#12-additional-freecommunity-feeds)
13. [Commercial/Freemium Feeds](#13-commercialfreemium-feeds)
14. [Aggregators & Meta-Feeds](#14-aggregators--meta-feeds)
15. [Known-Good / False Positive Reduction](#15-known-good--false-positive-reduction)
16. [Feed Directories & Indexes](#16-feed-directories--indexes)

---

## 1. abuse.ch Ecosystem

All abuse.ch services are **free** for non-commercial use. Commercial use may require a paid subscription via Spamhaus. The platform is hosted at Bern University of Applied Sciences (BFH) in Switzerland.

### 1.1 URLhaus

| Property | Value |
|----------|-------|
| **URL** | https://urlhaus.abuse.ch/ |
| **API** | https://urlhaus.abuse.ch/api/ |
| **Feed URL** | https://urlhaus.abuse.ch/downloads/csv_recent/ |
| **Format** | CSV, JSON (API) |
| **Indicator Types** | Malicious URLs (malware distribution) |
| **Update Frequency** | Continuous (API), CSV updated regularly |
| **Free** | Yes (fair use; commercial may need paid API) |
| **License** | CC0 |

### 1.2 MalwareBazaar

| Property | Value |
|----------|-------|
| **URL** | https://bazaar.abuse.ch/ |
| **API** | https://bazaar.abuse.ch/api/ |
| **Export** | https://bazaar.abuse.ch/export/ |
| **Format** | JSON (API), CSV (exports) |
| **Indicator Types** | Malware hashes (MD5, SHA256, SHA1, SHA3-384, imphash, tlsh, ssdeep), malware samples |
| **Update Frequency** | Continuous |
| **Free** | Yes (fair use) |
| **Notes** | Programmatic malware family classification via static/dynamic analysis. Each file unique in DB. |

### 1.3 ThreatFox

| Property | Value |
|----------|-------|
| **URL** | https://threatfox.abuse.ch/ |
| **API** | https://threatfox.abuse.ch/api/ |
| **Feed URL** | CSV feed available |
| **Format** | CSV, JSON (API) |
| **Indicator Types** | IOCs (IPs, domains, URLs, hashes) associated with malware |
| **Update Frequency** | Continuous; IOCs older than 6 months expired (since 2025-05-01) |
| **Free** | Yes |
| **Notes** | 1.7M+ IOCs shared. No STIX/TAXII (file too large). MISP feed available. |

### 1.4 Feodo Tracker

| Property | Value |
|----------|-------|
| **URL** | https://feodotracker.abuse.ch/ |
| **Blocklist** | https://feodotracker.abuse.ch/blocklist/ |
| **Format** | Plain text (IP list), JSON, Suricata/Snort rules |
| **Indicator Types** | Botnet C2 IPs (Dridex, Emotet, TrickBot, QakBot, BazarLoader) |
| **Update Frequency** | Every 5 minutes |
| **Free** | Yes (CC0) |
| **Key URLs** | |
| - IP Blocklist | `https://feodotracker.abuse.ch/downloads/ipblocklist.txt` |
| - IP Blocklist (JSON) | `https://feodotracker.abuse.ch/downloads/ipblocklist.json` |
| - Suricata Rules | `https://feodotracker.abuse.ch/downloads/suricata-rules.tar.gz` |

### 1.5 SSL Blacklist (SSLBL)

| Property | Value |
|----------|-------|
| **URL** | https://sslbl.abuse.ch/ |
| **Format** | CSV, Suricata rules, DNS RPZ |
| **Indicator Types** | SSL certificate SHA1 fingerprints, botnet C2 IPs, JA3 fingerprints |
| **Update Frequency** | Every 5 minutes |
| **Free** | Yes |
| **Key URLs** | |
| - SSL IP Blacklist (CSV) | `https://sslbl.abuse.ch/blacklist/sslipblacklist.csv` |
| - SSL Cert Blacklist (CSV) | `https://sslbl.abuse.ch/blacklist/sslblacklist.csv` |
| - JA3 Fingerprints (CSV) | `https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv` |
| - Aggressive IP Blacklist | `https://sslbl.abuse.ch/blacklist/sslipblacklist_aggressive.csv` |
| **Notes** | JA3 fingerprints may have high false-positive rate against legitimate traffic |

### 1.6 YARAify

| Property | Value |
|----------|-------|
| **URL** | https://yaraify.abuse.ch/ |
| **API** | https://yaraify-api.abuse.ch/api/v1/ |
| **Format** | JSON (API) |
| **Indicator Types** | YARA rule matches, file hashes, ClamAV signatures, imphash, tlsh |
| **Free** | Yes (requires free Auth-Key from auth.abuse.ch) |
| **Notes** | 110M+ files scanned, 23K+ YARA rules deployed. Supports file scanning, hash lookup, YARA rule deployment. |

---

## 2. AlienVault OTX / LevelBlue

| Property | Value |
|----------|-------|
| **URL** | https://otx.alienvault.com/ |
| **API** | https://otx.alienvault.com/api/v1/ |
| **Format** | JSON (native), CSV, STIX, OpenIOC 1.0/1.1 (export), TAXII |
| **Indicator Types** | IPs, domains, hostnames, URLs, file hashes (MD5, SHA1, SHA256, PEHASH, IMPHASH), email, CIDR, file paths, MUTEX, CVEs |
| **Update Frequency** | Continuous (community-driven pulses) |
| **Free** | Yes (100% free, requires registration for API key) |
| **Rate Limits** | Higher with API key vs. anonymous |
| **Scale** | 100K+ participants, 140+ countries, 19M+ indicators daily |
| **Notes** | Rebranded from AlienVault -> AT&T Cybersecurity -> LevelBlue (2024). Pulses are thematic threat reports with attached IOCs. DirectConnect API for automated pull. |

### Key API Endpoints

```
GET /api/v1/pulses/subscribed              # Your subscribed pulses
GET /api/v1/indicators/{type}/{indicator}   # Indicator lookup
GET /api/v1/pulses/indicators/types         # All supported indicator types
```

---

## 3. MITRE ATT&CK

| Property | Value |
|----------|-------|
| **URL** | https://attack.mitre.org/ |
| **STIX 2.1 Data (GitHub)** | https://github.com/mitre-attack/attack-stix-data |
| **STIX 2.0 Data (GitHub)** | https://github.com/mitre/cti |
| **TAXII Server** | Available (official ATT&CK TAXII server) |
| **Format** | STIX 2.1 JSON bundles (~48 MB for Enterprise) |
| **Content** | Techniques, tactics, groups, software, mitigations, data sources |
| **Domains** | Enterprise, Mobile, ICS |
| **Update Frequency** | Periodic releases (currently v18.1) |
| **Free** | Yes (fully open) |
| **Python Library** | `mitreattack-python` (pip install) |
| **TypeScript Library** | ATT&CK Data Model (ADM) |

### Direct Download URLs

```
# Enterprise ATT&CK (latest)
https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json

# Mobile ATT&CK (latest)
https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack.json

# ICS ATT&CK (latest)
https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json
```

---

## 4. VirusTotal

| Property | Value |
|----------|-------|
| **URL** | https://www.virustotal.com/ |
| **API Docs** | https://docs.virustotal.com/ |
| **Format** | JSON (API responses) |
| **Indicator Types** | File hashes (MD5, SHA1, SHA256), URLs, domains, IPs |
| **Free Tier** | Yes (Public API) |
| **Free Rate Limits** | 4 requests/min, 500/day, 15,500/month |
| **Hash Lookup** | Returns AV detections from 70+ engines, sandboxes |
| **Premium Features** | File downloads, Intelligence Search, full relationships, custom rate |
| **Notes** | No file download on free tier. Good for hash reputation checks. |

---

## 5. Phishing Feeds

### 5.1 PhishTank

| Property | Value |
|----------|-------|
| **URL** | https://www.phishtank.com/ |
| **API** | https://www.phishtank.com/developer_info.php |
| **Bulk Download** | `http://data.phishtank.com/data/<api_key>/online-valid.<format>` |
| **Formats** | JSON, CSV, XML, php_serialized (all bz2 compressed available) |
| **Indicator Types** | Phishing URLs with target brand info |
| **Update Frequency** | Hourly (bulk); real-time (API) |
| **Free** | Yes (requires free registration for API key) |
| **Operator** | Cisco Talos Intelligence Group |
| **CSV Fields** | phish_id, url, phish_detail_url, submission_time, verified, verification_time, online, target |

### 5.2 OpenPhish

| Property | Value |
|----------|-------|
| **URL** | https://openphish.com/ |
| **Community Feed** | https://openphish.com/feed.txt |
| **GitHub** | https://github.com/openphish/public_feed |
| **Format** | Plain text (URLs, one per line) |
| **Indicator Types** | Phishing URLs |
| **Update Frequency** | Every 12 hours (community); every 5 minutes (premium) |
| **Free** | Community feed is free; premium is paid (free for law enforcement/CERTs/academics) |
| **Notes** | Community feed = URLs only. Premium adds 15+ attributes (brand, industry, language, country). |

---

## 6. IP/Domain Reputation Feeds

### 6.1 Spamhaus

| Property | Value |
|----------|-------|
| **URL** | https://www.spamhaus.org/ |
| **DROP List** | https://www.spamhaus.org/drop/drop.txt |
| **EDROP List** | https://www.spamhaus.org/drop/edrop.txt |
| **Format** | Plain text (CIDR blocks), DNS-based (DNSBL/RPZ) |
| **Indicator Types** | Hijacked netblocks, spam sources, botnet C2s, phishing domains |
| **Products** | SBL (Spamhaus Block List), XBL (Exploits), PBL (Policy), DBL (Domain), DROP/EDROP |
| **Free** | DNS-based queries free for low-volume/non-commercial. Data feeds require subscription. |
| **Notes** | Protects 3B+ mailboxes. DROP = "Don't Route Or Peer" - professional cybercrime netblocks. |

### 6.2 DShield / SANS Internet Storm Center

| Property | Value |
|----------|-------|
| **URL** | https://www.dshield.org/ |
| **Blocklist** | https://www.dshield.org/block.txt |
| **Feeds Page** | https://www.dshield.org/xml.html |
| **Format** | Plain text, XML |
| **Indicator Types** | Top 20 attacking /24 subnets (last 3 days) |
| **Update Frequency** | Daily |
| **Free** | Yes |
| **Notes** | Community-based firewall log correlation. May contain false positives. |

### 6.3 Team Cymru

| Property | Value |
|----------|-------|
| **URL** | https://www.team-cymru.com/ |
| **Bogon List** | https://www.cymru.com/Documents/bogon-bn-agg.txt |
| **Format** | Plain text (CIDR) |
| **Indicator Types** | Bogon IPs (unallocated/reserved address space) |
| **Free** | Yes |
| **Notes** | Also offers IP-to-ASN mapping service, Fullbogons list. |

### 6.4 Emerging Threats (Proofpoint)

| Property | Value |
|----------|-------|
| **URL** | https://rules.emergingthreats.net/ |
| **IP Blocklist** | https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt |
| **Compromised IPs** | https://rules.emergingthreats.net/blockrules/compromised-ips.txt |
| **Format** | Plain text (IPs), Snort/Suricata rules |
| **Indicator Types** | Aggregated threat IPs (spam, DShield attackers, abuse.ch, etc.) |
| **Free** | Open ruleset is free; ET Pro requires subscription |
| **Notes** | Primary project is Snort/Suricata IDS rulesets. |

### 6.5 Blocklist.de

| Property | Value |
|----------|-------|
| **URL** | https://www.blocklist.de/ |
| **Export** | https://www.blocklist.de/en/export.html |
| **API** | https://www.blocklist.de/en/api.html |
| **Format** | Plain text (one IP per line), DNS RBL |
| **Indicator Types** | Attacking IPs by service type |
| **Update Frequency** | Every 48 hours (rolling window) |
| **Free** | Yes |
| **Key Lists** | |
| - SSH attacks | `https://lists.blocklist.de/lists/ssh.txt` |
| - Brute force logins | `https://lists.blocklist.de/lists/bruteforcelogin.txt` |
| - Strong IPs (>5000 attacks, >2 months) | `https://lists.blocklist.de/lists/strongips.txt` |
| - All | `https://lists.blocklist.de/lists/all.txt` |

### 6.6 AbuseIPDB

| Property | Value |
|----------|-------|
| **URL** | https://www.abuseipdb.com/ |
| **API Docs** | https://docs.abuseipdb.com/ |
| **Format** | JSON (API) |
| **Indicator Types** | IP reputation (abuse confidence score, country, ISP, usage type) |
| **Free Tier** | 1,000 checks+reports per day |
| **Free** | Yes (non-commercial); paid plans from $228/year |
| **Notes** | Community-driven IP abuse reporting. Returns abuseConfidenceScore (0-100). |

### 6.7 Cisco Talos IP Blacklist

| Property | Value |
|----------|-------|
| **URL** | https://www.talosintelligence.com/ |
| **IP Blacklist** | https://www.talosintelligence.com/documents/ip-blacklist |
| **IP Filter (BLF)** | http://www.talosintelligence.com/feeds/ip-filter.blf |
| **Format** | Plain text (one IP per line) |
| **Indicator Types** | Known malicious IPs |
| **Update Frequency** | Every 3 hours |
| **Free** | Yes (download); no public API for reputation |
| **Notes** | Based on telemetry from millions of deployed Cisco devices. |

### 6.8 IPsum (Aggregated)

| Property | Value |
|----------|-------|
| **URL** | https://github.com/stamparm/ipsum |
| **Format** | Plain text (IP + occurrence count) |
| **Indicator Types** | Suspicious/malicious IPs from 30+ blacklists |
| **Update Frequency** | Daily |
| **Free** | Yes |
| **Levels** | 1 (most inclusive, high FP) through 8 (most confident, low FP) |
| **Key URLs** | |
| - Level 1 | `https://raw.githubusercontent.com/stamparm/ipsum/master/levels/1.txt` |
| - Level 3 | `https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt` |
| - Level 5 | `https://raw.githubusercontent.com/stamparm/ipsum/master/levels/5.txt` |
| - Level 8 | `https://raw.githubusercontent.com/stamparm/ipsum/master/levels/8.txt` |

### 6.9 DataPlane.org

| Property | Value |
|----------|-------|
| **URL** | https://dataplane.org/ |
| **Format** | Plain text, CSV |
| **Indicator Types** | SSH attackers, DNS abuse, SIP abuse, VNC abuse |
| **Free** | Non-commercial only |
| **Key Feeds** | |
| - SSH Password Auth | `https://dataplane.org/sshpwauth.txt` |
| - SSH Client | `https://dataplane.org/sshclient.txt` |
| - DNS Recursion Desired | `https://dataplane.org/dnsrd.txt` |
| - DNS RD IN ANY | `https://dataplane.org/dnsrdany.txt` |
| **Notes** | 300+ nodes across 65 metro areas, 6 continents. 501(c)(3) nonprofit. |

### 6.10 GreyNoise

| Property | Value |
|----------|-------|
| **URL** | https://www.greynoise.io/ |
| **Community API** | `GET https://api.greynoise.io/v3/community/{ip}` |
| **Format** | JSON |
| **Indicator Types** | IP noise classification (malicious/benign/unknown), RIOT data |
| **Free** | Community API is free (unlimited lookups with free account) |
| **Response Fields** | noise, riot, classification, name, last_seen |
| **Notes** | Separates internet background noise from targeted attacks. RIOT = known benign services. |

---

## 7. Hash-Based IOC Feeds

### 7.1 MalwareBazaar (abuse.ch)

See [Section 1.2](#12-malwarebazaar) above.

### 7.2 MalShare

| Property | Value |
|----------|-------|
| **URL** | https://malshare.com/ |
| **API** | https://malshare.com/doc.php |
| **Format** | JSON (API), plain text hash lists |
| **Indicator Types** | Malware hashes (MD5, SHA1, SHA256), samples |
| **Free** | Yes (requires free account for API key) |
| **Key Endpoints** | `getlist` (24h hashes), `details`, `search`, `type` (list by type), `download` |
| **Notes** | Community-driven malware repository. Daily API request limits apply. |

### 7.3 VirusShare

| Property | Value |
|----------|-------|
| **URL** | https://virusshare.com/ |
| **Hash Lists** | https://virusshare.com/hashes |
| **Format** | Plain text (MD5, one per line) |
| **Indicator Types** | Malware MD5 hashes |
| **Free** | Hash lists are freely downloadable; sample downloads require approved account |
| **Scale** | 33M+ malware samples |
| **Notes** | Files 0-148: 131,072 hashes each (4.3 MB). Files 149+: 65,536 hashes each (2.1 MB). |

### 7.4 NSRL (National Software Reference Library)

| Property | Value |
|----------|-------|
| **URL** | https://www.nist.gov/itl/ssd/software-quality-group/national-software-reference-library-nsrl |
| **Download** | https://www.nist.gov/itl/ssd/software-quality-group/national-software-reference-library-nsrl/nsrl-download |
| **Format** | SQLite database (RDS v3, current); legacy CSV (RDS v2) |
| **Hash Algorithms** | MD5, SHA-1, SHA-256 |
| **Purpose** | Known software identification (NOT known-good; contains some malicious tools) |
| **Update Frequency** | Quarterly |
| **Free** | Yes |
| **Scale** | 40M+ hashes |
| **Notes** | Used for data REDUCTION in forensics (filter out known files). RDS v3 adds SHA256, versioning, file paths. NOT a whitelist - contains steganography tools, hacking scripts, etc. Compatible with md5deep, EnCase, FTK. |
| **Efficient NSRL** | https://github.com/DFIRScience/Efficient-NSRL (filtered/split version for DFIR) |

---

## 8. C2/Botnet/Ransomware Trackers

### 8.1 Feodo Tracker (abuse.ch)

See [Section 1.4](#14-feodo-tracker) above.

### 8.2 C2-Tracker (montysecurity)

| Property | Value |
|----------|-------|
| **URL** | https://github.com/montysecurity/C2-Tracker |
| **Format** | Plain text (one IP per file, per tool) |
| **Indicator Types** | C2 server IPs by tool/malware family |
| **Tracked Tools** | Cobalt Strike, Brute Ratel C4, Sliver, Metasploit, Havoc, Posh C2, and more |
| **Update Frequency** | Weekly (Mondays) |
| **Free** | Yes |
| **Key Files** | `all.txt` (all IPs), individual tool files |
| **Notes** | Uses Shodan to collect IPs. FortinetSIEM 7.2.0+ has native support. |

### 8.3 C2IntelFeeds (drb-ra)

| Property | Value |
|----------|-------|
| **URL** | https://github.com/drb-ra/C2IntelFeeds |
| **Format** | CSV |
| **Indicator Types** | C2 domains and IPs |
| **Key Feeds** | |
| - Domains + URLs + IPs (30-day) | `domainC2swithURLwithIP-30day-filter-abused.csv` |
| - Domain C2s | `domainC2s.csv` |
| - IP C2s | `IPC2s.csv` |
| **Free** | Yes |
| **Notes** | Integrable with Microsoft Defender/Sentinel via KQL. |

### 8.4 Bambenek Consulting

| Property | Value |
|----------|-------|
| **URL** | https://osint.bambenekconsulting.com/feeds/ |
| **Format** | CSV (plain text) |
| **Indicator Types** | DGA domains, C2 domains, C2 IPs |
| **Free** | DGA domain feeds are free OSINT; some IP feeds require license |
| **Key URLs** | |
| - C2 Domain Master (High Conf.) | `http://osint.bambenekconsulting.com/feeds/c2-dommasterlist-high.txt` |
| - DGA Feed | `https://faf.bambenekconsulting.com/feeds/dga-feed.txt` |
| - DGA Feed (High Conf., gzip) | `https://faf.bambenekconsulting.com/feeds/dga-feed-high.gz` |
| **Notes** | Covers 65+ malware families, ~1M domains. CSV format: `$ip,$description,$manpage`. |

---

## 9. Government CERT Feeds

### 9.1 CISA Automated Indicator Sharing (AIS)

| Property | Value |
|----------|-------|
| **URL** | https://www.cisa.gov/ais |
| **Format** | STIX 2.1 / TAXII 2.1 (AIS 2.0); legacy STIX 1.1 / TAXII 1.x (AIS 1.0) |
| **Indicator Types** | Malicious IPs, domains, URLs, email addresses, file hashes, TTPs |
| **Free** | Yes (no cost to participants) |
| **Participants** | Federal agencies, private sector, SLTT governments, ISACs/ISAOs, foreign partners |
| **How to Join** | Email cyberservices@cisa.dhs.gov; agree to Terms of Use; acquire STIX/TAXII client; get PKI certificate |
| **Legal** | CISA 2015 (extended through Sept 30, 2026). Liability protection for submitters. |
| **Notes** | Submissions anonymized by default. MISP integration via FLARE MISP Service. |

### 9.2 CISA Known Exploited Vulnerabilities (KEV)

| Property | Value |
|----------|-------|
| **URL** | https://www.cisa.gov/known-exploited-vulnerabilities-catalog |
| **Feed URL** | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json |
| **Format** | JSON, CSV |
| **Indicator Types** | CVEs actively exploited in the wild |
| **Free** | Yes |
| **Notes** | Mandatory for US federal agencies; excellent for prioritizing vulnerability remediation. |

### 9.3 CIS Real-Time Indicator Feeds

| Property | Value |
|----------|-------|
| **URL** | https://www.cisecurity.org/ms-isac/services/real-time-indicator-feeds |
| **Format** | Standard CTI formats (STIX/TAXII compatible) |
| **Indicator Types** | Malicious IPs, domains, URLs, hashes |
| **Free** | Yes (for US SLTT entities and election offices) |
| **Notes** | Includes a Federal Collection derived from CISA AIS. |

---

## 10. Tor Exit Node Lists

| Source | URL | Format | Update Freq. | Notes |
|--------|-----|--------|-------------|-------|
| **Tor Project (Official Bulk)** | `https://check.torproject.org/torbulkexitlist` | Plain text (one IP/line) | Hourly | Official source |
| **Tor Project (API)** | `https://check.torproject.org/api/bulk` | Plain text | Hourly | Current exit addresses from TorDNSEL |
| **Dan.me.uk (Exit Only)** | `https://www.dan.me.uk/torlist/?exit` | Plain text | Regular | IPv4 + IPv6 |
| **Dan.me.uk (All Nodes)** | `https://www.dan.me.uk/torlist/?full` | Plain text | Regular | All relay types |
| **Fission Relays** | `https://lists.fissionrelays.net/tor/exits.txt` | Plain text | Hourly (10 min after hour) | IPv4 + IPv6 |
| **SecOps Institute (GitHub)** | `https://github.com/SecOps-Institute/Tor-IP-Addresses` | Plain text | Hourly | Automated updates |

---

## 11. MISP Ecosystem

### 11.1 MISP Platform

| Property | Value |
|----------|-------|
| **URL** | https://www.misp-project.org/ |
| **Format** | MISP JSON (native), STIX 1.x/2.x, CSV, OpenIOC, Snort/Suricata, RPZ, free text |
| **Free** | Yes (open source, AGPLv3) |
| **Notes** | Full threat intelligence sharing platform. Default feeds included. |

### 11.2 MISP Default Feeds

MISP ships with many pre-configured feeds that just need enabling. Full list at: https://www.misp-project.org/feeds/

Notable default feeds include:

| Feed | Format | Type |
|------|--------|------|
| CIRCL OSINT Feed | MISP | Events with IOCs |
| Botvrij.eu | MISP | Various IOCs |
| inThreat.io | MISP | Curated threat data |
| CoinBlockerLists | Freetext | Crypto mining domains |
| Bambenek DGA C&Cs | CSV | DGA domains |
| Tor ALL Nodes / Exit Nodes | CSV | Tor IPs |
| IPsum (Levels 1-8) | Freetext | Aggregated bad IPs |
| ThreatFox IOCs | CSV | Malware IOCs |
| AlienVault Reputation | CSV | Malicious IPs |
| Cybercrime-tracker.net | Freetext | Botnet panels |
| DataPlane.org feeds | CSV | SSH/DNS abuse |
| ELLIO IP Feed | MISP | Scanning IPs |
| Infoblox TI | MISP | Various IOCs |

### 11.3 MISP Warning Lists

| Property | Value |
|----------|-------|
| **URL** | https://github.com/MISP/misp-warninglists |
| **Format** | JSON (`list.json` per directory) |
| **Matching Types** | hostname, cidr, regex |
| **Purpose** | False positive reduction - flag known-good infrastructure |
| **License** | CC0 |
| **Examples** | Public DNS resolvers, Amazon AWS IPs, Microsoft Azure IPs, Office 365 IPs, Akamai CDN, Alexa Top 1000, Cloudflare IPs, Google domains, RFC1918, Multicast, empty hash values, CRL/OCSP hosts, VPN ranges |

---

## 12. Additional Free/Community Feeds

### 12.1 Shadowserver Foundation

| Property | Value |
|----------|-------|
| **URL** | https://www.shadowserver.org/ |
| **Format** | CSV (reports delivered via email/API) |
| **Indicator Types** | Honeypot events (HTTP/RDP/SMB/ICS scanners), DDoS, malware URLs, brute force, sinkhole data |
| **Report Types** | 80+ distinct report types |
| **Update Frequency** | Daily |
| **Free** | Yes (for vetted subscribers: network owners, CERTs, governments) |
| **API** | Available (request API key upon signup) |
| **Notes** | Nonprofit. Trillions of historic data points. Reports include CVE/CVSS/MITRE ATT&CK mappings. |

### 12.2 Pulsedive

| Property | Value |
|----------|-------|
| **URL** | https://pulsedive.com/ |
| **API** | https://pulsedive.com/api/ |
| **Format** | JSON, CSV, STIX/TAXII |
| **Indicator Types** | IPs, domains, URLs with risk scores and enrichment |
| **Free** | Community tier is free (with API key) |
| **Notes** | Risk scoring algorithm, enrichment with DNS/SSL/WHOIS/HTTP data. Explore query language for bulk analysis. |

### 12.3 CyberCure

| Property | Value |
|----------|-------|
| **URL** | https://www.cybercure.ai/ |
| **API Docs** | https://docs.cybercure.ai/ |
| **Format** | CSV, STIX, CEF, Syslog |
| **Indicator Types** | Attacking IPs, malicious URLs, malware hashes (MD5) |
| **Free** | Yes (no API key required) |
| **Key Endpoints** | |
| - IPs | `http://api.cybercure.ai/feed/get_ips` |
| - URLs | `http://api.cybercure.ai/feed/get_url` |
| - Hashes | `https://api.cybercure.ai/feed/get_hash?type=csv` |
| **Notes** | Honeypot-sourced. Claims 0% false positive. Python SDK: `pip install cybercure`. |

### 12.4 Binary Defense Artillery Threat Intelligence

| Property | Value |
|----------|-------|
| **URL** | https://www.binarydefense.com/banlist.txt |
| **Format** | Plain text (one IP per line) |
| **Indicator Types** | Attacker IPs from Artillery honeypot |
| **Free** | Yes |

### 12.5 Phishing Army

| Property | Value |
|----------|-------|
| **URL** | https://phishing.army/ |
| **Feed** | https://phishing.army/download/phishing_army_blocklist.txt |
| **Format** | Plain text (domains) |
| **Indicator Types** | Phishing domains |
| **Free** | Yes |

### 12.6 CINSscore (Collective Intelligence Network Security)

| Property | Value |
|----------|-------|
| **URL** | https://cinsscore.com/ |
| **Feed** | https://cinsscore.com/list/ci-badguys.txt |
| **Format** | Plain text |
| **Indicator Types** | Bad IPs |
| **Free** | Yes |

---

## 13. Commercial/Freemium Feeds

### 13.1 Recorded Future

| Property | Value |
|----------|-------|
| **URL** | https://www.recordedfuture.com/ |
| **Free Offering** | Recorded Future Express (browser extension only) |
| **API** | Paid subscription required (5,000 calls/day included) |
| **Format** | Proprietary, STIX/TAXII via integrations |
| **Trial** | 30-day free trial via Microsoft Sentinel integration |
| **Notes** | No free community API. Enterprise-grade platform. Intelligence Graph indexes 1M+ sources. |

### 13.2 Mandiant / Google Threat Intelligence

| Property | Value |
|----------|-------|
| **URL** | https://cloud.google.com/security/products/mandiant-threat-intelligence |
| **Free Offering** | Mandiant Advantage Free (limited API access) |
| **API** | v4 API (subscription-based) |
| **Indicator Types** | IPs, URLs, domains, file hashes with IC-Score confidence |
| **Notes** | Backed by 200K+ hours/year of incident response work. |

### 13.3 CrowdStrike Falcon Intelligence

| Property | Value |
|----------|-------|
| **URL** | https://www.crowdstrike.com/ |
| **Free Offering** | None publicly documented |
| **API** | Falcon API (paid) |
| **Notes** | Adversary profiling, malware sandbox, 24/7 monitoring. Contact for pricing. |

### 13.4 IBM X-Force Exchange

| Property | Value |
|----------|-------|
| **URL** | https://exchange.xforce.ibmcloud.com/ |
| **Free Offering** | Yes (free tier for web portal and API) |
| **API** | X-Force Exchange API |
| **Format** | JSON, STIX/TAXII 2.0 |
| **Indicator Types** | IPs, URLs, malware, vulnerabilities, threat groups |
| **Notes** | Collaborative TIP with 1,000+ organizations. 30 years of vulnerability data. 150B+ events/day monitored. |

### 13.5 Palo Alto Unit 42 / AutoFocus

| Property | Value |
|----------|-------|
| **URL** | https://unit42.paloaltonetworks.com/ |
| **Free Offering** | Free public threat research reports; no free API tier |
| **API** | AutoFocus API (paid) |
| **Notes** | Human-curated research from Unit 42 team. Integrated with NGFW products. |

---

## 14. Aggregators & Meta-Feeds

### 14.1 IntelOwl

| Property | Value |
|----------|-------|
| **URL** | https://github.com/intelowlproject/IntelOwl |
| **Type** | Self-hosted OSINT aggregation platform |
| **Supported Analyzers** | 100+ (VirusTotal, AbuseIPDB, Spamhaus, OTX, Shodan, MalwareBazaar, GreyNoise, HudsonRock, etc.) |
| **Features** | REST API (Django/Python), playbooks, pivots, visualizers, connectors |
| **File Analysis** | YARA, Oletools, PE analysis (Blint), Go binary analysis (GoReSym), Nuclei scanning |
| **Free** | Yes (open source, AGPLv3) |
| **Notes** | Modular plugin architecture. Docker deployment. Maintained by Certego (MDR provider). |

### 14.2 FireHOL IP Lists

| Property | Value |
|----------|-------|
| **URL** | https://iplists.firehol.org/ |
| **GitHub** | https://github.com/firehol/blocklist-ipsets |
| **Format** | ipset format (plain text IPs/CIDRs) |
| **Sources** | 350+ IP blacklists aggregated |
| **Levels** | Level 1-4 (increasing coverage, increasing false positives) |
| **Free** | Yes |
| **Notes** | Aggregates DShield, Feodo, Fullbogons, Spamhaus, and many more. Updated dynamically. |

### 14.3 OpenCTI

| Property | Value |
|----------|-------|
| **URL** | https://filigran.io/platforms/opencti/ |
| **Type** | Self-hosted threat intelligence platform |
| **Format** | STIX 2.1 native |
| **Free** | Community edition is open source |
| **Notes** | Case management, threat hunting, SIEM/SOAR/EDR integration. By Filigran. |

---

## 15. Known-Good / False Positive Reduction

| Source | Purpose | URL |
|--------|---------|-----|
| **NSRL RDS** | Known software hashes (for file exclusion) | https://www.nist.gov/nsrl |
| **MISP Warning Lists** | Known-good IPs/domains (cloud, CDN, DNS) | https://github.com/MISP/misp-warninglists |
| **GreyNoise RIOT** | Known benign internet services | Built into GreyNoise Community API |
| **Alexa/Tranco Top Sites** | Legitimate high-traffic domains | https://tranco-list.eu/ |
| **DNSWL.org** | Whitelisted mail servers | https://www.dnswl.org/ |

---

## 16. Feed Directories & Indexes

These resources catalog available threat feeds:

| Resource | URL | Description |
|----------|-----|-------------|
| **Threatfeeds.io** | https://threatfeeds.io/ | Searchable directory of free TI feeds |
| **Threat-Intel.xyz** | https://www.threat-intel.xyz/ | Categorized list of IoC feeds |
| **Bert-JanP/Open-Source-Threat-Intel-Feeds** | https://github.com/Bert-JanP/Open-Source-Threat-Intel-Feeds | CSV catalog of all free feeds with direct URLs |
| **Awesome Threat Intelligence** | https://github.com/hslatman/awesome-threat-intelligence | Curated list of TI resources and tools |
| **MISP Default Feeds** | https://www.misp-project.org/feeds/ | All feeds that ship with MISP |

---

## Integration Priority Matrix for Forensic Triage

### Tier 1: Essential (No API key, instant integration)

| Feed | Use Case | Format |
|------|----------|--------|
| NSRL RDS | Filter known files from analysis | SQLite/CSV |
| Feodo Tracker Blocklist | Detect botnet C2 connections | Plain text / JSON |
| URLhaus Recent URLs | Flag malware distribution URLs | CSV |
| Tor Exit Node List | Flag Tor-sourced connections | Plain text |
| Spamhaus DROP/EDROP | Block hijacked netblocks | Plain text |
| DShield Top Attackers | Flag attacking subnets | Plain text |
| IPsum Level 3+ | Aggregated bad IPs | Plain text |
| OpenPhish Community | Detect phishing URLs | Plain text |
| Cisco Talos IP Blacklist | Known bad IPs | Plain text |
| CyberCure Feeds | IPs, URLs, hashes (no key needed) | CSV/STIX |
| C2-Tracker | C2 infrastructure IPs | Plain text |
| MITRE ATT&CK | TTP mapping for findings | STIX 2.1 JSON |

### Tier 2: High Value (Free API key required)

| Feed | Use Case | Format |
|------|----------|--------|
| VirusTotal | Hash/URL/IP reputation lookup | JSON |
| AlienVault OTX | Multi-indicator enrichment | JSON |
| MalwareBazaar | Malware hash lookup | JSON |
| ThreatFox | IOC enrichment | JSON/CSV |
| PhishTank | Phishing URL verification | JSON/CSV |
| AbuseIPDB | IP abuse confidence scoring | JSON |
| GreyNoise Community | Noise vs targeted classification | JSON |
| YARAify | YARA rule matching | JSON |
| Pulsedive | IOC risk scoring | JSON |
| MalShare | Malware hash lookup | JSON |
| SSLBL | SSL/JA3 fingerprint matching | CSV |

### Tier 3: Advanced (Registration/approval required)

| Feed | Use Case | Format |
|------|----------|--------|
| CISA AIS | Government threat indicators | STIX/TAXII |
| Shadowserver | Comprehensive threat reports | CSV |
| IBM X-Force Exchange | Threat intelligence enrichment | JSON/STIX |
| Mandiant Advantage Free | High-confidence indicators | JSON |
| MISP (self-hosted) | Full TI platform with 50+ feeds | Multiple |

---

## Data Format Summary

| Format | Feeds Using It | Parsing Complexity |
|--------|---------------|-------------------|
| **Plain text (one indicator/line)** | IPsum, Tor lists, DShield, blocklist.de, C2-Tracker, Talos, Spamhaus DROP | Trivial |
| **CSV** | URLhaus, ThreatFox, Feodo, SSLBL, PhishTank, Bambenek, DataPlane | Low |
| **JSON** | VirusTotal, OTX, MalwareBazaar, AbuseIPDB, GreyNoise, Pulsedive, CISA KEV | Medium |
| **STIX 2.1** | MITRE ATT&CK, CISA AIS, OpenCTI, CyberCure (optional) | Medium-High |
| **MISP JSON** | MISP feeds, CIRCL OSINT | Medium |
| **Suricata/Snort Rules** | Emerging Threats, Feodo Tracker, SSLBL | Specialized |
| **SQLite** | NSRL RDS v3 | Low |
| **DNS/RPZ** | Spamhaus, SSLBL, blocklist.de | Specialized |
