# Zerox

Zerox is an open-source vulnerability scanner designed to detect XSS, SQLi, SSRF, and IDOR vulnerabilities. It includes an endpoint discovery module using the Wayback Machine and web crawling.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/Stalin-143/ZeroX.git
   cd zerox
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

Run the scanner with one of the input options:

```bash
# Scan a single URL (discovers additional endpoints)
python main.py --url http://localhost/vulnapp --scan all

# Scan a list of URLs
python main.py --list urls.txt --scan xss

# Scan using Burp Suite export
python main.py --burp burp_export.json

# Specify output files and debug mode
python main.py --url http://localhost/vulnapp --scan all --output report.json --markdown vuln.md --debug
```

## Supported Vulnerabilities
- **XSS**: Tests for reflected and stored XSS with payloads like `<script>alert(1)</script>`.
- **SQLi**: Detects SQL injection with payloads like `' OR '1'='1` and time-based checks.
- **SSRF**: Tests for server-side request forgery (requires a collaborator server like webhook.site).
- **IDOR**: Checks for insecure direct object references by manipulating IDs.
- **Endpoint Discovery**: Uses Wayback Machine and crawling to find endpoints.

## Output
- JSON report (`report.json`): Detailed findings in JSON format.
- Markdown report (`vuln.md`): Human-readable summary of vulnerabilities.

## Project Structure
```
zerox/
├── scanners/
│   ├── __init__.py
│   ├── xss.py
│   ├── sqli.py
│   ├── ssrf.py
│   ├── idor.py
│   └── endpoint_finder.py
├── utils/
│   ├── __init__.py
│   ├── parser.py
│   ├── reporter.py
│   └── logger.py
├── main.py
├── requirements.txt
└── README.md
```

## Testing with VulnApp
Set up the VulnApp web application locally to test Zerox safely:
```bash
python main.py --url http://localhost/vulnapp/search.php?query=test --scan xss --debug
```

## Notes
- **SSRF Testing**: Update `scanners/ssrf.py` with a webhook.site URL and check logs for requests.
- **Legal Use**: Test only on authorized environments like VulnApp or testphp.vulnweb.com.
- **Enhancements**: Add POST form parsing, authentication support, or more payloads.

## Contributing
Contributions are welcome! Please open an issue or submit a pull request.

## License
MIT License