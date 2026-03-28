<p align="center">
  <img src="assets/ollama_scanner.png" alt="OLLAMA REMOTE SERVER SCANNER" width="600">
</p>

Ollama Scanner v4.2 – Installation & Usage Guide

This tool scans IP ranges for open LLM servers (Ollama, LM Studio, TextGen WebUI) and reports available models, loaded processes, and model configurations.

Prerequisites

· Python 3.7 or higher
· pip (Python package manager)

Installation

1. Clone or download the script:
   ```bash
   git clone https://github.com/your-repo/ollama-scanner.git
   cd ollama-scanner
   ```
   Or simply download Ollama_Scanner_v4.2.py to your machine.
2. Install required dependencies:
   ```bash
   pip install -r requirements.txt
   ```
   If you prefer to install them manually:
   ```bash
   pip install aiohttp tqdm
   ```
   Note: tqdm is optional – the scanner will work without it, but the progress bar will be simpler.

Basic Usage

```bash
python Ollama_Scanner_v4.2.py <target>
```

Where <target> can be:

· A single IP: 192.168.1.10
· CIDR range: 192.168.1.0/24
· Range notation: 192.168.1.1-100
· IPv6 address or CIDR: 2001:db8::/32

Command-Line Options

Argument Description
range IP range to scan (if not using --file).
-f, --file File containing IP addresses/ranges (one per line).
-p, --port Port to scan (default: 11434).
-t, --timeout Connection timeout in seconds (default: 5.0).
-c, --concurrent Maximum concurrent connections (default: 100).
-r, --retries Number of retry attempts per target (default: 3).
-d, --retry-delay Base delay between retries (seconds, default: 0.5).
-o, --output Base name for output files (JSON report + TXT list).
--deep Perform deep scan: query loaded models and model configurations.
-v, --verbose Enable debug logging.
--no-progress Suppress progress display.
--no-ssl-verify Disable SSL certificate verification (for HTTPS servers).
--disable-dns-cache Disable DNS caching (default is enabled).

Examples

1. Scan a /24 subnet for Ollama servers on port 11434

```bash
python Ollama_Scanner_v4.2.py 192.168.1.0/24
```

2. Scan a range of IPs with a custom port (e.g., LM Studio on 1234)

```bash
python Ollama_Scanner_v4.2.py 192.168.1.1-100 -p 1234
```

3. Deep scan to retrieve loaded models and configurations

```bash
python Ollama_Scanner_v4.2.py 10.0.0.0/24 --deep
```

4. Scan targets from a file and save results

```bash
python Ollama_Scanner_v4.2.py --file targets.txt -o scan_results
```

The output will create:

· scan_results_report_<timestamp>.json – full JSON report
· scan_results.txt – list of server URLs

5. Increase concurrency and timeout for faster scans on a large network

```bash
python Ollama_Scanner_v4.2.py 172.16.0.0/16 -c 200 -t 3
```

Output

· Standard output (stdout): Discovered servers and model lists are printed in real‑time.
· Standard error (stderr): Progress, statistics, and logs are displayed.
· Reports: If -o is specified, a JSON file with all details and a plain text list of URLs are saved.

Important Disclaimer

This tool is intended for authorized network administrators only.
Scanning networks without explicit permission may violate local laws and regulations. The authors assume no liability for misuse. Always obtain proper authorization before scanning any network.

Troubleshooting

· tqdm not installed: The script will work but progress will be displayed as text.
· High memory usage: For extremely large ranges (e.g., /8), consider splitting into smaller ranges.
· Timeout errors: Increase -t or reduce -c if the network is slow.
· SSL errors: Use --no-ssl-verify if scanning servers with self‑signed certificates.

For additional help, run:

```bash
python Ollama_Scanner_v4.2.py -h
```

---

Version: 4.2.0
Last Updated: 2026
