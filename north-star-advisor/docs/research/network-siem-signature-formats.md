# Network & SIEM Signature Formats Research

> Research date: 2026-03-22 | Covers formats current as of 2025-2026

## 1. Zeek (formerly Bro)

### Intel Framework
- Tab-separated text files with `#fields` header
- Fields: `indicator`, `indicator_type` (Intel::ADDR, Intel::DOMAIN, Intel::URL, Intel::FILE_NAME, Intel::FILE_HASH, Intel::EMAIL), `meta.source`, `meta.desc`, `meta.url`
- Load via: `redef Intel::read_files += { "/path/feed.txt" };`
- Matches logged to `intel.log`
- Default: only established TCP IPs reported; extensible via scripts

### Offline PCAP
- Fully supported: `zeek -r file.pcap` (add `-C` for checksum errors)
- Generates conn.log, dns.log, http.log, ssl.log, etc.
- Custom scripts: `zeek myscript.zeek -r file.pcap`
- UIDs correlate across log files

### Public Intel Feeds
- [CriticalPathSecurity/Zeek-Intelligence-Feeds](https://github.com/CriticalPathSecurity/Zeek-Intelligence-Feeds) - aggregates Abuse.ch, AlienVault, OpenPhish
- [Malcolm](https://malcolm.fyi/docs/zeek-intel.html) - auto-converts STIX/TAXII and MISP JSON to Zeek intel

### Key Docs
- https://docs.zeek.org/en/master/frameworks/intel.html
- https://docs.zeek.org/en/current/quickstart.html

---

## 2. Suricata/Snort Rules

### Suricata Rule Format (7.x+)
```
action protocol src_ip src_port -> dst_ip dst_port (options;)
```
- Actions: alert, pass, drop, reject
- Protocols: tcp, udp, http, tls, dns, smtp, etc.
- Key options: `msg`, `content`, `flow`, `sid`, `rev`, `classtype`, `pcre`, `fast_pattern`
- Protocol-specific: `http.uri`, `http.host`, `tls.sni`, `dns.query`

### Rule Feeds
| Feed | Status | License | URL |
|------|--------|---------|-----|
| ET Open | Active | MIT | https://rules.emergingthreats.net/open/suricata/rules/ |
| ET Pro | Active | Commercial | Via suricata-update with secret-code |
| Snort 3 Community | Active | GPLv2 | https://www.snort.org/downloads/community/snort3-community-rules.tar.gz |
| Feodo Tracker | Active | CC0 | https://feodotracker.abuse.ch/downloads/feodotracker.tar.gz |
| URLhaus | Active | Free | https://urlhaus.abuse.ch/downloads/suricata-ids/ |
| SSLBL | **DEPRECATED** 2025-01-03 | - | Discontinued |
| OISF TrafficID | Active | MIT | Via suricata-update |
| PT Research | Active | Custom | Via suricata-update |

- Full source index: https://github.com/OISF/suricata-intel-index/blob/master/index.yaml
- Management: `suricata-update` (bundled with Suricata)

### Offline PCAP Analysis
```bash
suricata -r file.pcap                    # single file
suricata -r file.pcap -S custom.rules    # exclusive rules
suricata -r /path/to/dir/               # directory
suricata -r /dir/ --pcap-file-recursive  # recursive
```

### Rust Crates
- **evebox-suricata-rule-parser**: Suricata rule parser (v0.2.0 yanked, check latest). https://docs.rs/evebox-suricata-rule-parser
- **pcap-parser** (rusticata): Zero-copy PCAP/PCAPNG parser. https://crates.io/crates/pcap-parser
- **pcap** (rust-pcap): libpcap bindings. https://crates.io/crates/pcap
- No mature standalone Rust crate for IDS rule parsing exists yet

### Other Tools
- [Dalton](https://github.com/secureworks/dalton) - Web-based PCAP testing against Suricata/Snort/Zeek
- [gonids](https://github.com/google/gonids) (Go) - IDS rule parser

---

## 3. Splunk SPL / SIEM Detection Rules

### Splunk ESCU
- 1,900+ detections mapped to MITRE ATT&CK
- YAML format with SPL in `search` field
- GitHub: https://github.com/splunk/security_content
- Portal: https://research.splunk.com
- Build tool: https://github.com/splunk/contentctl

### Sigma Rules (Universal Detection Format)
- YAML-based, SIEM-agnostic detection rules
- 3,000+ rules: https://github.com/SigmaHQ/sigma
- Spec: https://github.com/SigmaHQ/sigma-specification
- Structure: `title`, `id` (UUID), `logsource` (category/product/service), `detection` (selection + condition), `level`
- Detection: maps=AND, lists=OR; field modifiers: `|contains`, `|endswith`, `|startswith`, `|re`

### Translating to Local Timeline DB
**pySigma SQLite Backend** is the key integration point:
- https://github.com/SigmaHQ/pySigma-backend-sqlite
- Converts Sigma rules to SQLite WHERE clauses
- Compatible with **Zircolite** (https://github.com/wagga40/Zircolite):
  - Standalone forensic detection on EVTX, Auditd, Sysmon, JSON logs
  - Pure SQLite queries from Sigma rules
  - Export to JSON, CSV, Timesketch, Splunk, Elastic

### Other SIEM Detection Content
| Source | Format | URL |
|--------|--------|-----|
| Elastic Detection Rules | TOML + KQL/EQL | https://github.com/elastic/detection-rules |
| Azure/Microsoft Sentinel | JSON + KQL | https://github.com/Azure/Azure-Sentinel |
| Community KQL (Bert-JanP) | KQL | https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules |
| Sigma pre-built for Elastic | Sigma->Lucene | https://github.com/j91321/elastic-sigma |

---

## 4. STIX/TAXII Threat Intelligence

### STIX 2.1 Indicator Format
```json
{
  "type": "indicator",
  "spec_version": "2.1",
  "id": "indicator--<uuid>",
  "pattern": "[ipv4-addr:value = '198.51.100.1']",
  "pattern_type": "stix",
  "valid_from": "2025-01-01T00:00:00Z"
}
```
- Pattern examples: IP, domain, file hash (SHA-256), URL, email, sequential (FOLLOWEDBY)
- SCOs: File, Process, Network Traffic, IPv4/6, Domain, URL, Email, Registry Key, etc.
- Spec: https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html

### Public TAXII Feeds
| Source | Access | URL |
|--------|--------|-----|
| AlienVault OTX | Free (API key) | `https://otx.alienvault.com/taxii/` |
| CISA AIS | US entities | Via CISA enrollment |
| CIS/MS-ISAC | Members | Via membership |
| MITRE ATT&CK (STIX) | Free | https://github.com/mitre-attack/attack-stix-data |
| ESET | Commercial | Via subscription |

### Using STIX for Scanning
1. Extract patterns from Indicator objects
2. Parse pattern language for observable values (hashes, IPs, domains)
3. Match against forensic artifacts (file hashes, network logs, DNS, registry)
4. Simple equality patterns convertible to Zeek intel format
5. Complex patterns (FOLLOWEDBY, WITHIN) need correlation engine

### Rust Crates
- **cti** (TedDriggs): STIX 2.0 types, WIP. https://github.com/TedDriggs/cti
- **threat-intel** (redasgard): Multi-source aggregation. https://github.com/redasgard/threat-intel
- No mature STIX 2.1 or TAXII 2.1 Rust crate exists yet

---

## 5. Other Signature/Indicator Formats

### OpenIOC (Mandiant)
- XML-based, Apache 2.0 license
- Boolean AND/OR logic combining indicators (hashes, registry, memory, network)
- Spec: https://github.com/mandiant/OpenIOC_1.1
- Tools: IOC Editor (free GUI), `ioc_writer` (Python)
- Limited adoption outside Mandiant ecosystem

### MISP (Malware Information Sharing Platform)
- Central hub: imports/exports virtually all formats
- Exports to: Suricata/Snort/Zeek, STIX, OpenIOC, KQL, osquery, CSV, JSON
- GitHub: https://github.com/MISP/MISP
- Website: https://www.misp-project.org/

### osquery Packs
- SQL-based endpoint queries in JSON pack format
- Key repos:
  - [osquery-defense-kit](https://github.com/chainguard-dev/osquery-defense-kit) (Chainguard, production-ready)
  - [Recon Hunt Queries](https://rhq.reconinfosec.com/) (ATT&CK-mapped)
  - [ThreatHunting_with_Osquery](https://github.com/Kirtar22/ThreatHunting_with_Osquery) (100+ queries)
  - [osquery-attck](https://github.com/teoseller/osquery-attck) (MITRE mapped)
- Covers: persistence, process analysis, network, file system (Windows/Linux/macOS)

### KQL Detections
- Used by Microsoft Sentinel and Microsoft 365 Defender/XDR
- Sigma convertible to KQL via pySigma backend
- MISP can export directly as Defender KQL queries
- Key resource: https://kqlquery.com

### ClamAV Signatures
- Docs: https://docs.clamav.net/manual/Signatures.html
- **Hash signatures** (.hdb/.hsb): `MD5/SHA1/SHA256:FileSize:MalwareName`
- **Extended signatures** (.ndb): `Name:TargetType:Offset:HexSignature`
  - Wildcards: `??` (any byte), `*` (any length), `{n-m}` (range)
- **Logical signatures** (.ldb): Boolean combinations of up to 64 subsignatures
- **PE section hashes** (.mdb/.msb), **PE import table hashes** (.imp)
- Unofficial sigs: https://github.com/extremeshok/clamav-unofficial-sigs
- Test: `clamscan -d custom.ndb /path/to/scan`

### YARA Rules
- Already covered in YARA/YARA-X research
- De facto standard for malware file classification
- yara-x crate provides native Rust support

---

## Integration Strategy Summary

### For a Rust-based forensic triage tool:

**Directly parseable in Rust:**
- Zeek intel feeds (tab-separated, trivial to parse)
- ClamAV hash signatures (colon-separated, trivial)
- STIX 2.1 JSON (via serde_json, pattern language needs custom parser)
- Sigma YAML (via serde_yaml, condition logic needs custom evaluator)
- osquery packs JSON (via serde_json)
- YARA rules (via yara-x crate)

**Require external tools for deep analysis:**
- Suricata rules on PCAPs (shell out to `suricata -r`)
- Zeek scripts on PCAPs (shell out to `zeek -r`)
- Sigma->SQLite conversion (via Python pySigma or implement backend in Rust)

**Format conversion via MISP:**
- MISP serves as universal converter between all formats
- Can pre-convert intel to tool-native formats

### Recommended Priority
1. **YARA** (already researched, yara-x native Rust)
2. **Sigma rules + SQLite backend** (broadest detection coverage, Zircolite model)
3. **STIX 2.1 indicators** (extract simple IoCs: hashes, IPs, domains)
4. **Suricata offline PCAP** (shell out to suricata -r for network artifacts)
5. **Zeek intel feeds** (simple format, easy parsing)
6. **ClamAV hash sigs** (simple format for quick file checks)
7. **osquery packs** (if live endpoint querying is in scope)
