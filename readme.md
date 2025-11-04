# GCP Identifier (`gcp_identifier.py`)

A Python 3 tool to **passively identify Google Cloud Platform (GCP) hosting** using a three-phase OSINT methodology.
Outputs a human-readable report to stdout and raw JSON logs to a file. Optionally exports a self-contained HTML report.

---

## Phases

1. **Phase 1 – Certificate Transparency (CT) Log Analysis**
   Discovers subdomains and notes certificates issued by Google Trust Services (historical indicator `CT-01`).

2. **Phase 2 – DNS Interrogation**
   Resolves discovered domains/subdomains and checks for live indicators:

   * `DNS-01` – `google-site-verification` TXT
   * `DNS-02` – CNAME → `ghs.googlehosted.com`
   * `DNS-03` – MX → Google Workspace (`ASPMX.L.GOOGLE.COM`, etc.)
   * `DNS-04` – SPF includes `_spf.google.com`
   * `DNS-05` – NS suggests Google Cloud DNS (`ns-cloud-*.googledomains.com`)

3. **Phase 3 – Network Infrastructure Mapping (IP→ASN)**
   Maps IPs to ASNs and records live indicators:

   * `ASN-01A` – AS396982 (GOOGLE-CLOUD-PLATFORM)
   * `ASN-01B` – AS16550 (GOOGLE-PRIVATE-CLOUD)
   * `ASN-01C` – AS394089 (GCP-ENTERPRISE-USER-TRAFFIC)
   * `ASN-02`  – AS15169 (GOOGLE)
   * `ASN-03`  – Other Google ASNs (e.g., AS36040, AS43515)

---

## Scoring & Reporting

* Calculates a **confidence score** from active (DNS/ASN) indicators.
* Prints a final **report and score** with tables (to stdout).
* Writes structured **JSON logs** to a file named `gcp_profiler_<domain>_<timestamp>.json`.
* Optional **HTML report** export via `--html`.

---

## Requirements

* **Python** ≥ 3.6

### Dependencies

Install with:

```bash
pip install dnspython requests ipwhois rich
```

---

## Usage

Basic:

```bash
python3 gcp_identifier.py <domain.com>
```

Verbose mode (prints all findings, including historical, during analysis):

```bash
python3 gcp_identifier.py <domain.com> -v
```

Export HTML report:

```bash
python3 gcp_identifier.py <domain.com> --html example_report.html
```

### Arguments

* `domain` (positional): Target domain (e.g., `example.com`)
* `-v, --verbose`: Verbose output during analysis
* `--html FILE_PATH`: Write a self-contained HTML report to `FILE_PATH`

---

## Output

* **Stdout**: Colored/structured summary (uses `rich`)
* **JSON log file**: Detailed raw data and events
* **HTML report** (optional): Self-contained summary of findings and score

---

## Internals (High-Level)

* **Phase 1**: `phase1_ct_analysis(domain, logger, printer)`
* **Phase 2**: `phase2_dns_mapping(target, logger, printer)`
* **Phase 3**: `phase3_asn_mapping(ip, logger, printer)`
* **DNS helper**: `query_dns_record(target, record_type)`
* **Scoring**: `Scorer`
* **Logging**: JSON via `JsonFormatter`
* **CLI Orchestration**: `main(domain, verbose, html_file)`

