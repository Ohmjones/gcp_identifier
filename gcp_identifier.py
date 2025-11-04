#!/usr/bin/env python3

"""
GCP Identifier (gcp_identifier.py)

A Python 3 tool to passively identify Google Cloud Platform (GCP) hosting
based on the methodology described in "A Methodology for Passive Attribution
of Google Cloud Platform Hosting."

This tool performs a three-phase OSINT analysis based on reliable OSINT methodology,
executing them in an optimized order for maximum effectiveness:
1. (Phase 1) Certificate Transparency (CT) Log Analysis: Discovers all subdomains.
2. (Phase 2) DNS Interrogation: Queries all discovered subdomains for DNS records.
3. (Phase 3) Network Infrastructure Mapping: Analyzes all discovered IPs for ASN ownership.

Outputs a human-readable report to stdout and raw JSON logs to a file.

Dependencies:
    pip install dnspython requests ipwhois rich

Usage:
    python3 gcp_identifier.py <domain.com>
    python3 gcp_identifier.py <domain.com> -v  (For verbose output)
    python3 gcp_identifier.py <domain.com> --html report.html (To export an HTML report)
"""

import argparse, json, logging, random, requests, sys, time 
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
from datetime import datetime
from ipwhois import IPWhois
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

# Import DNS libraries
try:
    import dns.resolver
    import dns.exception
except ImportError:
    print(
        "Error: 'dnspython' module not found. Please install it with 'pip install dnspython'",
        file=sys.stderr
    )
    sys.exit(1)

# Import Rich libraries
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
except ImportError:
    print(
        "Error: 'rich' module not found. Please install it with 'pip install rich'",
        file=sys.stderr
    )
    sys.exit(1)

# --- Rich-based Printer ---
class Printer:
    """Handles colored printing to stdout using rich, aware of verbosity."""
    def __init__(self, verbose=False):
        self.verbose_mode = verbose
        # Create a console object for rich printing
        self.console = Console()

    def info(self, message):
        """Prints blue info messages. [>>]"""
        self.console.print(f"\t[blue][>>] {message}[/blue]")

    def success(self, message):
        """Prints green success messages. [+]"""
        self.console.print(f"\t[green][+] {message}[/green]")

    def warning(self, message):
        """Prints yellow warning messages. [!]"""
        self.console.print(f"\t[yellow][!] {message}[/yellow]")

    def critical(self, message):
        """Prints red critical messages. [!]"""
        self.console.print(f"\t[red][!] {message}[/red]")
    
    def finding(self, item, value, indent=1):
        """Prints a magenta item and its cyan value (a Google-related indicator)."""
        tabs = "  " * indent # Use spaces for better alignment in rich
        #self.console.print(f"{tabs}[magenta][>>] {item}:[/magenta] [cyan]{value}[/cyan]")
        self.console.print(f"\t[magenta][>>] {item}:[/magenta] [cyan]{value}[/cyan]")

    def verbose(self, item, value, indent=1):
        """Prints a verbose-only finding."""
        if self.verbose_mode:
            tabs = "  " * indent
            # Use a less "loud" color for verbose
            self.console.print(f"{tabs}[dim][v] {item}:[/dim] {value}")

    def header(self, title):
        """Prints a main header as a rich Panel."""
        self.console.print() # Add a newline for spacing
        self.console.print(Panel(title.upper(), style="blue", expand=False))

    def final_score(self, score_text, confidence_text, style):
        """Prints the final score in a prominent panel."""
        self.console.print()
        score_panel = Panel(
            Text(f"{score_text} -> {confidence_text}", justify="center"),
            title="Total Score [Active Indicators Only]",
            style=style,
            expand=False
        )
        self.console.print(score_panel)

# --- JSON Logging ---
class JsonFormatter(logging.Formatter):
    """Formats log records as JSON objects."""
    def format(self, record):
        log_object = {
            'timestamp': self.formatTime(record, self.datefmt),
            'level': record.levelname,
            'phase': getattr(record, 'phase', 'general'),
            'target': getattr(record, 'target', 'N/A'),
            'type': getattr(record, 'type', 'log'),
            'data': record.getMessage(),
        }
        if record.exc_info:
            log_object['exception'] = self.formatException(record.exc_info)
        return json.dumps(log_object)

def setup_logging(domain):
    """Configures logging to a JSON file."""
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    log_filename = f"gcp_profiler_{domain.replace('.', '_')}_{timestamp}.json"
    
    logger = logging.getLogger("gcp_profiler")
    logger.setLevel(logging.DEBUG)
    
    # Prevent logs from propagating to root logger (which might print to console)
    logger.propagate = False

    # File handler for JSON logs
    handler = logging.FileHandler(log_filename)
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)
    
    return logger, log_filename

# --- Scoring Model ---
class Scorer:
    """Calculates and reports a GCP confidence score."""
    
    INDICATORS = {
        # Critical (50 pts) - Direct GCP/Cloud Hosting Confirmation
        'ASN-01A': {'points': 50, 'type': 'live', 'desc': 'IP in primary GCP ASN (AS396982, GOOGLE-CLOUD-PLATFORM)'},
        'ASN-01B': {'points': 50, 'type': 'live', 'desc': 'IP in Private Cloud ASN (AS16550, GOOGLE-PRIVATE-CLOUD)'},
        'ASN-01C': {'points': 50, 'type': 'live', 'desc': 'IP in GCP Enterprise ASN (AS394089, GCP-ENTERPRISE-USER-TRAFFIC)'},
        
        # High (30 pts) - Strong Relationship / Probable Hosting
        'DNS-02': {'points': 30, 'type': 'live', 'desc': 'CNAME points to ghs.googlehosted.com'},
        'ASN-02': {'points': 30, 'type': 'live', 'desc': 'IP in primary Google Services ASN (AS15169, GOOGLE)'},
        
        # Medium (15 pts) - Correlated Services
        'DNS-01': {'points': 15, 'type': 'live', 'desc': 'google-site-verification TXT Record'},
        'DNS-03': {'points': 15, 'type': 'live', 'desc': 'MX records point to Google Workspace'},
        'DNS-04': {'points': 15, 'type': 'live', 'desc': 'SPF record includes _spf.google.com'},
        
        # Low (5 pts) - Circumstantial
        'DNS-05': {'points': 5, 'type': 'live', 'desc': 'NS records point to Google Cloud DNS'},
        'ASN-03': {'points': 5, 'type': 'live', 'desc': 'IP in Google Global Cache ASN (e.g., AS36040, AS43515)'},

        # No Points - Historical        
        'CT-01':  {'points': 0, 'type': 'historical', 'desc': 'Certificate *historically* issued by Google Trust Services (Context-Only, 0 pts)'},
    }
    
    OTHER_GOOGLE_ASNS = {
        'AS36040': 'Google Global Cache / YOUTUBE',
        'AS43515': 'Google Services and Peering'
    }

    def __init__(self, logger, printer):
        self.logger = logger
        self.printer = printer
        self.findings = defaultdict(list)
        self.score = 0
        self.live_findings = []
        self.historical_findings = []
        self.bonus_applied = False

    def add_finding(self, indicator_id, target, detail):
        """Adds a discovered finding to be scored."""
        if indicator_id not in self.INDICATORS:
            return
            
        self.findings[indicator_id].append({
            'target': target,
            'detail': detail
        })
        self.logger.info(
            f"Indicator {indicator_id} found for {target}",
            extra={'phase': 'scoring', 'target': target, 'type': 'indicator'}
        )

    def calculate_score(self):
        """Calculates the total score based on unique indicators."""
        self.score = 0
        found_indicator_types = set()
        
        for indicator_id in self.findings:
            base_id = indicator_id.rstrip('ABCDEFGHIJKLMNOPQRSTUVWXYZ')
            found_indicator_types.add(base_id)

        for base_id in found_indicator_types:
            full_id = next((id for id in self.INDICATORS if id.startswith(base_id)), None)
            if full_id:
                self.score += self.INDICATORS[full_id]['points']

        # Corroboration Bonus only for LIVE data
        phases = set()
        for indicator_id in self.findings:
            if self.INDICATORS[indicator_id]['type'] == 'live':
                if indicator_id.startswith('DNS-'):
                    phases.add('DNS')
                elif indicator_id.startswith('ASN-'):
                    phases.add('ASN')
        
        if len(phases) >= 2:
            self.bonus_applied = True
            self.score += 10
            
        return self.score

    def get_confidence_tier(self, score):
        if score > 100:
            return "Critical Confidence (101+)", "red"
        if score > 80:
            return "High Confidence (81-100)", "magenta"
        if score > 50:
            return "Moderate Confidence (51-80)", "yellow"
        if score > 20:
            return "Low Confidence (21-50)", "cyan"
        return "Very Low Confidence (0-20)", "dim"
    
    def _prepare_findings(self):
        """Internal helper to sort findings for reporting."""
        if self.live_findings or self.historical_findings:
             return # Already prepared
             
        for indicator_id, details in self.findings.items():
            info = self.INDICATORS[indicator_id]
            if info['type'] == 'live':
                self.live_findings.append((indicator_id, details, info))
            else:
                self.historical_findings.append((indicator_id, details, info))

        # Sort by points
        self.live_findings.sort(key=lambda x: x[2]['points'], reverse=True)
        self.historical_findings.sort(key=lambda x: x[2]['points'], reverse=True)

    def print_report(self):
        """Prints the final scoring report to stdout using rich tables."""
        self._prepare_findings()
        self.printer.header("Final Report & Confidence Score")
        
        if not self.findings:
            self.printer.info("No scorable indicators were found.")
            
        # Print Live Findings
        if self.live_findings:
            live_table = Table(title="==> Active Indicators Found [Live DNS & ASN Data]", title_style="green", expand=True)
            live_table.add_column("Indicator", style="green", no_wrap=True)
            live_table.add_column("Points", style="cyan", no_wrap=True)
            live_table.add_column("Description", style="white")
            live_table.add_column("Target", style="magenta")
            live_table.add_column("Detail", style="cyan")

            for indicator_id, details, info in self.live_findings:
                first = True
                for finding in details:
                    if first:
                        live_table.add_row(
                            indicator_id, 
                            f"(+{info['points']} pts)", 
                            info['desc'], 
                            finding['target'], 
                            finding['detail']
                        )
                        first = False
                    else:
                        live_table.add_row("", "", "", finding['target'], finding['detail'])
            
            self.printer.console.print(live_table)
        else:
            self.printer.info("No Active Indicators Found.")

        # Print Historical Findings
        if self.historical_findings:
            hist_table = Table(title="==> Historical Indicators Found [Past CT Log Data]", title_style="green", expand=True)
            hist_table.add_column("Indicator", style="dim", no_wrap=True)
            hist_table.add_column("Points", style="dim", no_wrap=True)
            hist_table.add_column("Description", style="dim")
            hist_table.add_column("Target", style="dim")
            hist_table.add_column("Detail", style="dim")

            for indicator_id, details, info in self.historical_findings:
                first = True
                for finding in details:
                    if first:
                        hist_table.add_row(
                            indicator_id, 
                            f"(+{info['points']} pts)", 
                            info['desc'], 
                            finding['target'], 
                            finding['detail']
                        )
                        first = False
                    else:
                        hist_table.add_row("", "", "", finding['target'], finding['detail'])
            
            self.printer.console.print(hist_table)
        
        if not self.live_findings and not self.historical_findings:
             self.printer.info("No scorable indicators were found.")

        if self.bonus_applied:
            self.printer.success("Applying 10-point Corroboration Bonus (live indicators from >1 phase)")

        final_score = self.calculate_score()
        confidence, style = self.get_confidence_tier(final_score)
        
        self.printer.final_score(f"Score: {final_score}", confidence, style)

def phase1_ct_analysis(domain, logger, printer):
    """
    Queries crt.sh for subdomains and certificate issuers.
    Returns a set of unique subdomains found and a list of *unique*
    potential CT-01 indicators.
    """
    from urllib.parse import quote
    import subprocess

    printer.header(f"Phase 1: Certificate Transparency Analysis for {domain}")
    logger.info(
        f"Starting Phase 1 for {domain}",
        extra={'phase': '1', 'target': domain, 'type': 'start'}
    )

    # This set will contain all subdomains found for Phase 1
    master_subdomain_list = {domain, f"www.{domain}"}

    # Key: (id, target, issuer), Value: [list of dates]
    unique_ct_indicators = defaultdict(list)

    # Build the crt.sh URL with URL-encoded wildcard (%.example.com -> %25.example.com)
    q = quote(f"%.{domain}", safe="")
    url = f"https://crt.sh/?q={q}&output=json"

    # ---- Robust fetch with Retry + HTML guard + curl fallback ----
    raw_data = None
    session = requests.Session()
    retry = Retry(
        total=6,
        connect=3,
        read=3,
        status=6,
        backoff_factor=1.5,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(["GET"]),
        raise_on_status=False,
        respect_retry_after_header=True,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_maxsize=4)
    session.mount("https://", adapter)
    session.mount("http://", adapter)

    headers = {
        "Accept": "application/json",
        "User-Agent": (
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
        ),
        "Connection": "close",
    }

    try:
        # Shorter per-attempt timeout; retries handle transient crt.sh slowness
        resp = session.get(url, timeout=60, headers=headers)
        text = resp.text or ""
        # Guard against HTML error pages with 200 status
        if "<html" in text.lower():
            raise ValueError("Non-JSON HTML received from crt.sh")
        raw_data = resp.json()
    except Exception as e_http:
        # Log the failure and try a curl fallback since you've observed curl works
        logger.warning(
            f"requests path failed for crt.sh: {e_http}",
            extra={'phase': '1', 'target': domain, 'type': 'warning', 'source': 'crt.sh'}
        )
        cmd = [
            "curl", "-sS", "--fail", "--location",
            "--max-time", "60",
            "--retry", "4", "--retry-delay", "2",
            "-H", "Accept: application/json",
            "-H", f"User-Agent: {headers['User-Agent']}",
            url
        ]
        try:
            out = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
            text = out.decode("utf-8", "replace")
            if "<html" in text.lower():
                raise ValueError("curl fallback received HTML instead of JSON")
            raw_data = json.loads(text)
        except subprocess.CalledProcessError as cpe:
            logger.error(
                f"curl fallback failed: {cpe.output.decode('utf-8', 'replace')}",
                extra={'phase': '1', 'target': domain, 'type': 'error', 'source': 'crt.sh'}
            )
            printer.critical(f"Failed to query crt.sh: curl fallback failed (see log).")
            printer.info(f"Phase 1 completed. Total unique sub/domains to review: {len(master_subdomain_list)}")
            return master_subdomain_list, []
        except json.JSONDecodeError as jde:
            logger.error(
                f"curl fallback returned non-JSON content: {jde}",
                extra={'phase': '1', 'target': domain, 'type': 'error', 'source': 'crt.sh'}
            )
            printer.critical(f"Failed to parse crt.sh response as JSON.")
            printer.info(f"Phase 1 completed. Total unique sub/domains to review: {len(master_subdomain_list)}")
            return master_subdomain_list, []

    # If we reach here, we have some JSON-ish content
    try:
        logger.debug(
            raw_data,
            extra={'phase': '1', 'target': domain, 'type': 'raw_data', 'source': 'crt.sh'}
        )
    except Exception:
        # Defensive: raw_data might be large/unserializable for the logger; ignore debug failures
        pass

    if not raw_data:
        printer.info("No certificates found in CT logs.")
        printer.info(f"Phase 1 completed. Total unique sub/domains to review: {len(master_subdomain_list)}")
        return master_subdomain_list, []

    found_subdomains_from_ct = set()

    # Normalize crt.sh records (some outputs can be a dict or list)
    records = raw_data if isinstance(raw_data, list) else [raw_data]
    for cert in records:
        if not isinstance(cert, dict):
            continue

        issuer_name = cert.get('issuer_name', '')

        # Create a list of all names in this one cert
        subdomains_in_this_cert = set()

        common_name = cert.get('common_name', 'N/A')
        if common_name != 'N/A' and isinstance(common_name, str) and domain in common_name:
            cn = common_name.lower().strip()
            if cn.startswith('*.'):
                cn = cn[2:]
            if cn:
                subdomains_in_this_cert.add(cn)

        name_values = cert.get('name_value', '')
        if isinstance(name_values, str):
            names_iter = name_values.split('\n')
        elif isinstance(name_values, list):
            # Rarely seen, but be safe
            names_iter = name_values
        else:
            names_iter = []

        for name in names_iter:
            if not isinstance(name, str):
                continue
            name = name.strip().lower()
            if name and domain in name:
                if name.startswith('*.'):
                    name = name[2:]
                if name:
                    subdomains_in_this_cert.add(name)

        # Add all these subdomains to the master list for Phase 1
        for sub in subdomains_in_this_cert:
            found_subdomains_from_ct.add(sub)
            master_subdomain_list.add(sub)

        # --- Check for Google Trust Services indicator ---
        if "Google Trust Services LLC" in issuer_name:
            entry_timestamp = cert.get('entry_timestamp', 'N/A')
            entry_date = entry_timestamp.split('T')[0] if isinstance(entry_timestamp, str) and entry_timestamp != 'N/A' else 'N/A'
            for target_sub in subdomains_in_this_cert:
                indicator_key = ('CT-01', target_sub, issuer_name)
                unique_ct_indicators[indicator_key].append(entry_date)

    printer.success(f"Discovered {len(records)} certificates, finding {len(found_subdomains_from_ct)} unique subdomains.")

    # --- Print de-duplicated verbose findings ---
    for sub in sorted(list(found_subdomains_from_ct)):
        printer.verbose("Found Subdomain", sub, indent=1)

    printer.info(f"Phase 1 completed. Total unique sub/domains to review: {len(master_subdomain_list)}")

    # De-duplicate, find the latest date, and format the output
    ct_indicators_list = []
    for (id, target, issuer), dates in unique_ct_indicators.items():
        # De-duplicate dates and find latest
        uniq = sorted(set(d for d in dates if isinstance(d, str) and d))
        latest_date = uniq[-1] if uniq else 'N/A'
        detail_string = f"Issuer: {issuer} (Last Seen: {latest_date})"
        ct_indicators_list.append({
            'id': id,
            'target': target,
            'detail': detail_string
        })
        # Keep your original verbose line for historical issuer
        printer.verbose(f"Historical Issuer for {target}", f"Google Trust Services LLC (Last Seen: {latest_date})", indent=1)

    return master_subdomain_list, ct_indicators_list


# --- Phase 1: DNS Interrogation ---
def query_dns_record(target, record_type):
    """Helper function to perform a single DNS query."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2.0
        resolver.lifetime = 2.0
        answers = resolver.resolve(target, record_type)
        return [str(rdata) for rdata in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        return []
    except dns.exception.Timeout:
        return ["Query Timed Out"]
    except Exception as e:
        return [f"Error: {e}"]

def phase2_dns_mapping(target, logger, printer):
    """
    Performs DNS interrogation for a single target (domain/subdomain).
    Returns:
        - set of IPs
        - list of indicators
        - boolean is_resolvable (for the sanity check)
    """
    logger.info(
        f"Starting Phase 2 for {target}",
        extra={'phase': '2', 'target': target, 'type': 'start'}
    )
    
    ips = set()
    indicators = []
    log_data = {'target': target, 'records': {}}
    is_resolvable = False

    # A (IPv4)
    a_records = query_dns_record(target, 'A')
    if a_records:
        log_data['records']['A'] = a_records
        for ip in a_records:
            if not ip.startswith("Error"):
                ips.add(ip)
                printer.verbose(f"{target} A", ip, indent=1)
                is_resolvable = True

    # AAAA (IPv6)
    aaaa_records = query_dns_record(target, 'AAAA')
    if aaaa_records:
        log_data['records']['AAAA'] = aaaa_records
        for ip in aaaa_records:
            if not ip.startswith("Error"):
                ips.add(ip)
                printer.verbose(f"{target} AAAA", ip, indent=1)
                is_resolvable = True
    
    # CNAME (Canonical Name)
    cname_records = query_dns_record(target, 'CNAME')
    if cname_records:
        is_resolvable = True # A CNAME means it's "live"
        log_data['records']['CNAME'] = cname_records
        for record in cname_records:
            record_clean = record.rstrip('.')
            if "ghs.googlehosted.com" in record_clean:
                indicators.append({
                    'id': 'DNS-02',
                    'target': target,
                    'detail': f"CNAME -> {record_clean}"
                })
                # This is a LIVE indicator, print it
                printer.finding(f"{target} CNAME", record_clean, indent=1)
            else:
                printer.verbose(f"{target} CNAME", record_clean, indent=1)
    
    # Only query these records for the root domain
    if target == domain:
        # NS (Name Server)
        ns_records = query_dns_record(target, 'NS')
        if ns_records:
            log_data['records']['NS'] = ns_records
            for record in ns_records:
                record_clean = record.rstrip('.')
                # More robust check for Google Cloud DNS
                if "ns-cloud-" in record_clean and "googledomains.com" in record_clean:
                    indicators.append({
                        'id': 'DNS-05',
                        'target': target,
                        'detail': f"NS -> {record_clean}"
                    })
                    printer.finding(f"{target} NS", record_clean, indent=1)
                else:
                    printer.verbose(f"{target} NS", record_clean, indent=1)
        
        # MX (Mail Exchange)
        mx_records = query_dns_record(target, 'MX')
        if mx_records:
            log_data['records']['MX'] = mx_records
            for record in mx_records:
                record_clean = record.split(' ')[-1].rstrip('.')
                if "smtp.google.com" in record_clean or "ASPMX.L.GOOGLE.COM" in record_clean.upper():
                    indicators.append({
                        'id': 'DNS-03',
                        'target': target,
                        'detail': f"MX -> {record_clean}"
                    })
                    printer.finding(f"{target} MX", record_clean, indent=1)
                else:
                    printer.verbose(f"{target} MX", record_clean, indent=1)
        
        # TXT (Text Records)
        txt_records = query_dns_record(target, 'TXT')
        if txt_records:
            log_data['records']['TXT'] = txt_records
            for record in txt_records:
                record_clean = record.strip('"')
                if "google-site-verification=" in record_clean:
                    indicators.append({
                        'id': 'DNS-01',
                        'target': target,
                        'detail': record_clean
                    })
                    printer.finding(f"{target} TXT", record_clean.split('=')[0] + "=...", indent=1)
                elif "include:_spf.google.com" in record_clean:
                    indicators.append({
                        'id': 'DNS-04',
                        'target': target,
                        'detail': record_clean
                    })
                    printer.finding(f"{target} TXT", "SPF includes _spf.google.com", indent=1)
                else:
                    printer.verbose(f"{target} TXT", record_clean[:70] + "...", indent=1)

    logger.debug(
        log_data,
        extra={'phase': '2', 'target': target, 'type': 'raw_data'}
    )
    return ips, indicators, is_resolvable

# --- Phase 3: Network Infrastructure Mapping ---
def phase3_asn_mapping(ip, logger, printer):
    """
    Performs IP-to-ASN lookup for a single IP.
    Returns a list of indicators.
    """
    logger.info(
        f"Starting Phase 3 for {ip}",
        extra={'phase': '3', 'target': ip, 'type': 'start'}
    )
    
    indicators = []
    
    try:
        obj = IPWhois(ip)
        results = obj.lookup_whois(inc_raw=False)
        
        logger.debug(
            results,
            extra={'phase': '3', 'target': ip, 'type': 'raw_data', 'source': 'ipwhois'}
        )
        
        asn = results.get('asn', 'N/A')
        asn_desc = results.get('asn_description', 'N/A')
        
        if asn == '396982':
            indicators.append({
                'id': 'ASN-01A',
                'target': ip,
                'detail': f"AS396982 (GOOGLE-CLOUD-PLATFORM) - {asn_desc}"
            })
            printer.finding(f"IP {ip} ASN", f"AS396982 (GOOGLE-CLOUD-PLATFORM)", indent=1)
        elif asn == '16550':
            indicators.append({
                'id': 'ASN-01B',
                'target': ip,
                'detail': f"AS16550 (GOOGLE-PRIVATE-CLOUD) - {asn_desc}"
            })
            printer.finding(f"IP {ip} ASN", f"AS16550 (GOOGLE-PRIVATE-CLOUD)", indent=1)
        elif asn == '394089':
            indicators.append({
                'id': 'ASN-01C',
                'target': ip,
                'detail': f"AS394089 (GCP-ENTERPRISE-USER-TRAFFIC) - {asn_desc}"
            })
            printer.finding(f"IP {ip} ASN", f"AS394089 (GCP-ENTERPRISE-USER-TRAFFIC)", indent=1)
        elif asn == '15169':
            indicators.append({
                'id': 'ASN-02',
                'target': ip,
                'detail': f"AS15169 (GOOGLE) - {asn_desc}"
            })
            printer.finding(f"IP {ip} ASN", f"AS15169 (GOOGLE)", indent=1)
        elif asn in Scorer.OTHER_GOOGLE_ASNS:
            indicators.append({
                'id': 'ASN-03',
                'target': ip,
                'detail': f"AS{asn} ({Scorer.OTHER_GOOGLE_ASNS[asn]}) - {asn_desc}"
            })
            printer.finding(f"IP {ip} ASN", f"AS{asn} ({Scorer.OTHER_GOOGLE_ASNS[asn]})", indent=1)
        else:
            printer.verbose(f"IP {ip} ASN", f"AS{asn} ({asn_desc})", indent=1)

    except Exception as e:
        logger.error(
            str(e),
            extra={'phase': '3', 'target': ip, 'type': 'error'}
        )
        
    return indicators

# --- HTML Report Generator ---
def generate_html_report(domain, scorer, html_file_path):
    """Generates a self-contained HTML report of the findings."""
    
    scorer._prepare_findings() # Ensure findings are sorted
    
    # Get score and confidence
    final_score = scorer.calculate_score()
    confidence, style = scorer.get_confidence_tier(final_score)
    
    # Map rich/terminal colors to CSS classes
    style_to_class = {
        "red": "critical",
        "magenta": "high",
        "yellow": "moderate",
        "cyan": "low",
        "dim": "very-low"
    }
    confidence_class = style_to_class.get(style, "low")

    # --- HTML & CSS Template ---
    html_template = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>GCP Identifier Report: {domain}</title>
        <style>
            body {{
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
                background-color: #f4f7f6;
                color: #333;
                margin: 0;
                padding: 20px;
            }}
            .container {{
                max-width: 1200px;
                margin: 0 auto;
                background-color: #ffffff;
                border: 1px solid #ddd;
                border-radius: 8px;
                box-shadow: 0 4px 12px rgba(0,0,0,0.05);
                overflow: hidden;
            }}
            header {{
                background-color: #4285F4; /* Google Blue */
                color: white;
                padding: 20px 30px;
                border-bottom: 1px solid #ddd;
            }}
            header h1 {{
                margin: 0;
                font-size: 24px;
            }}
            header p {{
                margin: 5px 0 0;
                font-size: 16px;
                opacity: 0.9;
            }}
            .summary {{
                padding: 30px;
                border-bottom: 1px solid #eee;
                text-align: center;
            }}
            .summary h2 {{
                margin: 0 0 10px 0;
                color: #555;
            }}
            .score-box {{
                display: inline-block;
                padding: 15px 30px;
                border-radius: 8px;
                font-size: 20px;
                font-weight: bold;
            }}
            /* Confidence Classes */
            .critical {{ background-color: #EA4335; color: white; }}
            .high {{ background-color: #E040FB; color: white; }}
            .moderate {{ background-color: #FBBC05; color: #333; }}
            .low {{ background-color: #4285F4; color: white; }}
            .very-low {{ background-color: #f1f1f1; color: #555; }}

            .content {{ padding: 30px; }}
            h3 {{
                font-size: 20px;
                color: #34A853; /* Google Green */
                border-bottom: 2px solid #eee;
                padding-bottom: 10px;
                margin-top: 0;
            }}
            h3.historical {{ color: #777; }}
            table {{
                width: 100%;
                border-collapse: collapse;
                margin-bottom: 30px;
            }}
            th, td {{
                border: 1px solid #ddd;
                padding: 12px 15px;
                text-align: left;
                vertical-align: top;
            }}
            th {{
                background-color: #f9f9f9;
                font-weight: 600;
            }}
            tr:nth-child(even) {{ background-color: #fdfdfd; }}
            td:nth-child(1) {{ font-weight: bold; color: #34A853; width: 10%; }}
            td:nth-child(2) {{ color: #555; width: 8%; }}
            td:nth-child(4) {{ color: #d942a4; width: 20%; word-break: break-all; }}
            td:nth-child(5) {{ word-break: break-all; }}
            .no-findings {{
                color: #777;
                font-style: italic;
            }}
            footer {{
                text-align: center;
                padding: 20px;
                font-size: 12px;
                color: #999;
                border-top: 1px solid #eee;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <header>
                <h1>GCP Identifier Report</h1>
                <p>Target Domain: <strong>{domain}</strong></p>
            </header>

            <div class="summary">
                <h2>Confidence Score</h2>
                <div class="score-box {confidence_class}">
                    {final_score} &rarr; {confidence}
                </div>
            </div>

            <div class="content">
    """

    # --- Add Live Indicators Table ---
    html_template += "<h3>Active Indicators [Live DNS & ASN Data]</h3>"
    if scorer.live_findings:
        html_template += """
                <table>
                    <thead>
                        <tr>
                            <th>Indicator</th>
                            <th>Points</th>
                            <th>Description</th>
                            <th>Target</th>
                            <th>Detail</th>
                        </tr>
                    </thead>
                    <tbody>
        """
        for indicator_id, details, info in scorer.live_findings:
            first = True
            for finding in details:
                if first:
                    html_template += f"""
                        <tr>
                            <td>{indicator_id}</td>
                            <td>(+{info['points']} pts)</td>
                            <td>{info['desc']}</td>
                            <td>{finding['target']}</td>
                            <td>{finding['detail']}</td>
                        </tr>
                    """
                    first = False
                else:
                    html_template += f"""
                        <tr>
                            <td></td>
                            <td></td>
                            <td></td>
                            <td>{finding['target']}</td>
                            <td>{finding['detail']}</td>
                        </tr>
                    """
        html_template += "</tbody></table>"
    else:
        html_template += "<p class='no-findings'>No Active Indicators Found.</p>"

    # --- Add Historical Indicators Table ---
    html_template += "<h3 class='historical'>Historical Indicators (Past CT Log Data)</h3>"
    if scorer.historical_findings:
        html_template += """
                <table>
                    <thead>
                        <tr>
                            <th>Indicator</th>
                            <th>Points</th>
                            <th>Description</th>
                            <th>Target</th>
                            <th>Detail</th>
                        </tr>
                    </thead>
                    <tbody>
        """
        for indicator_id, details, info in scorer.historical_findings:
            first = True
            for finding in details:
                if first:
                    html_template += f"""
                        <tr>
                            <td style="color: #777;">{indicator_id}</td>
                            <td style="color: #777;">(+{info['points']} pts)</td>
                            <td style_ "color: #777;">{info['desc']}</td>
                            <td style="color: #777;">{finding['target']}</td>
                            <td style="color: #777;">{finding['detail']}</td>
                        </tr>
                    """
                    first = False
                else:
                    html_template += f"""
                        <tr>
                            <td></td>
                            <td></td>
                            <td></td>
                            <td style="color: #777;">{finding['target']}</td>
                            <td style="color: #777;">{finding['detail']}</td>
                        </tr>
                    """
        html_template += "</tbody></table>"
    else:
        html_template += "<p class='no-findings'>No Historical Indicators Found.</p>"
    
    # --- Close HTML ---
    html_template += f"""
            </div>
            <footer>
                Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            </footer>
        </div>
    </body>
    </html>
    """
    
    # --- Write the file ---
    try:
        with open(html_file_path, 'w', encoding='utf-8') as f:
            f.write(html_template)
        return True
    except Exception as e:
        return e

# --- Main Orchestrator ---
def main(domain, verbose, html_file):
    """Main function to orchestrate the three-phase methodology."""
    
    printer = Printer(verbose)
    logger, log_filename = setup_logging(domain)
    scorer = Scorer(logger, printer)
    
    printer.header(f"GCP Identifier Started for: {domain}")
    printer.info(f"Raw JSON logs will be written to: {log_filename}")

    all_ips = set()
    dns_indicators = []
    asn_indicators = []
    
    try:
    # Phase 1)
        subdomains, ct_indicators = phase1_ct_analysis(domain, logger, printer)
    except Exception as e:
        printer.critical(f"Critical error during Phase 1: {e}")
        logger.critical(str(e), extra={'phase': '1', 'target': domain, 'type': 'critical_error'})
        subdomains = {domain, f"www.{domain}"} # Fallback
        ct_indicators = []

    # Phase 2)
    printer.header(f"Phase 2: DNS Interrogation for {len(subdomains)} targets")
    resolvable_subdomains = set() 
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(phase2_dns_mapping, sub, logger, printer): sub for sub in subdomains}
        
        for future in as_completed(futures):
            target_subdomain = futures[future]
            try:
                ips, indicators, is_resolvable = future.result()
                all_ips.update(ips)
                dns_indicators.extend(indicators)
                if is_resolvable:
                    resolvable_subdomains.add(target_subdomain)
            except Exception as e:
                logger.error(str(e), extra={'phase': '2', 'target': target_subdomain, 'type': 'error'})

    if not dns_indicators and not printer.verbose_mode:
        printer.info("No scorable DNS indicators found.")

    # Phase 3)
    printer.header(f"Phase 3: ASN Mapping for {len(all_ips)} unique IPs")
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(phase3_asn_mapping, ip, logger, printer): ip for ip in all_ips}
        
        for future in as_completed(futures):
            try:
                indicators = future.result()
                asn_indicators.extend(indicators)
            except Exception as e:
                target = futures[future]
                logger.error(str(e), extra={'phase': '3', 'target': target, 'type': 'error'})

    # --- Scoring & Correlation ---
    
    # Add all live DNS and ASN indicators
    for finding in (dns_indicators + asn_indicators):
        scorer.add_finding(finding['id'], finding['target'], finding['detail'])
    
    # *** DNS Sanity Check ***
    printer.info(f"Correlating {len(ct_indicators)} historical CT findings with {len(resolvable_subdomains)} live assets...")
    validated_ct_count = 0
    for finding in ct_indicators:
        if finding['target'] in resolvable_subdomains:
            validated_ct_count += 1
            scorer.add_finding(finding['id'], finding['target'], finding['detail'])
        else:
            printer.verbose(f"Ignoring stale CT finding", f"{finding['target']} (no longer resolves)")

    if validated_ct_count > 0:
        printer.success(f"Validated {validated_ct_count} historical CT indicators against live assets.")
    else:
        printer.info("No historical CT indicators could be validated against live assets.")
        
    scorer.print_report()
    
    # --- HTML Report Generation ---
    if html_file:
        printer.info(f"Generating HTML report at {html_file}...")
        result = generate_html_report(domain, scorer, html_file)
        if result is True:
            printer.success(f"Successfully wrote HTML report to {html_file}")
        else:
            printer.critical(f"Failed to write HTML report: {result}")
            
    printer.info(f"Analysis complete.")


if __name__ == "__main__":
    if sys.version_info < (3, 6):
        print("Error: This script requires Python 3.6 or later.", file=sys.stderr)
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description="GCP Identifier: Passively identifies GCP hosting.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""Examples:
  # Run in default quiet mode (only shows active hits & summary)
  python3 gcp_identifier.py example.com

  # Run in verbose mode (shows all findings, including historical, during analysis)
  python3 gcp_identifier.py example.com -v
  
  # Export a professional HTML report
  python3 gcp_identifier.py example.com --html example_report.html
"""
    )
    parser.add_argument(
        "domain",
        help="The target domain to analyze (e.g., example.com)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Print all findings to stdout, including historical ones, during analysis."
    )
    parser.add_argument(
        "--html",
        metavar="FILE_PATH",
        help="Export a self-contained HTML report to the specified file."
    )
    
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)
        
    args = parser.parse_args()
    
    # Store domain globally for the root-domain-only checks
    domain = args.domain.lower().strip()
    
    main(domain, args.verbose, args.html)
