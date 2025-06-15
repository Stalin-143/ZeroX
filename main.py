import argparse
import json
import os
import time
from scanners.xss import XSSScanner
from scanners.sqli import SQLiScanner
from scanners.ssrf import SSRFScanner
from scanners.idor import IDORScanner
from scanners.endpoint_finder import EndpointFinder
from utils.reporter import generate_json_report, generate_markdown_report
from utils.logger import setup_logger

VERSION = "1.0.0"

def main():
    parser = argparse.ArgumentParser(
        description="Zerox: Open-source vulnerability scanner for XSS, SQLi, SSRF, and IDOR",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-u", "--url", help="Single target URL to scan or file containing URLs")
    parser.add_argument("--endpoint", help="Output file for endpoint discovery (e.g., end.txt)")
    parser.add_argument("-o", "--output", help="Output JSON report file (default: report.json)", default="report.json")
    parser.add_argument("--markdown", help="Output Markdown report file (default: vuln.md)", default="vuln.md")
    parser.add_argument("--scan", choices=["xss", "sqli", "ssrf", "idor", "all"], default="all",
                        help="Specify scan type (default: all)")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("-v", "--version", action="version", version=f"Zerox {VERSION}",
                        help="Show version and exit")
    parser.add_argument("--burp", help="Burp Suite export file (JSON/HTTP history)")

    args = parser.parse_args()
    logger = setup_logger()

    # Initialize results list
    results = []
    logger.info("Starting Zerox scan...")

    # Handle input sources
    urls = []
    if args.url:
        if os.path.isfile(args.url):
            with open(args.url, "r") as f:
                urls = [line.strip() for line in f if line.strip()]
            logger.info(f"Loaded {len(urls)} URLs from {args.url}")
        else:
            urls.append(args.url)
            logger.info(f"Scanning single URL: {args.url}")
            # Perform endpoint discovery if --endpoint is specified
            if args.endpoint:
                endpoint_finder = EndpointFinder()
                urls = endpoint_finder.find_endpoints(args.url)
                logger.info(f"Discovered {len(urls)} endpoints for {args.url}")
                try:
                    with open(args.endpoint, "w") as f:
                        f.write("\n".join(urls))
                    logger.info(f"Saved endpoints to {args.endpoint}")
                except Exception as e:
                    logger.error(f"Error saving endpoints to {args.endpoint}: {e}")
    elif args.burp and os.path.exists(args.burp):
        with open(args.burp, "r") as f:
            burp_data = json.load(f)
            urls = [item["url"] for item in burp_data if "url" in item]
        logger.info(f"Loaded {len(urls)} URLs from Burp export")

    # Run scanners based on --scan argument
    for url in urls:
        if args.scan in ["xss", "all"]:
            xss_scanner = XSSScanner()
            logger.info(f"Scanning {url} for XSS...")
            findings = xss_scanner.scan(url)
            results.extend(findings)

        if args.scan in ["sqli", "all"]:
            sqli_scanner = SQLiScanner()
            logger.info(f"Scanning {url} for SQLi...")
            findings = sqli_scanner.scan(url)
            results.extend(findings)

        if args.scan in ["ssrf", "all"]:
            ssrf_scanner = SSRFScanner()
            logger.info(f"Scanning {url} for SSRF...")
            findings = ssrf_scanner.scan(url)
            results.extend(findings)

        if args.scan in ["idor", "all"]:
            idor_scanner = IDORScanner()
            logger.info(f"Scanning {url} for IDOR...")
            findings = idor_scanner.scan(url)
            results.extend(findings)

        time.sleep(1)  # Avoid rate-limiting

    # Generate reports
    if results:
        generate_json_report(results, args.output)
        generate_markdown_report(results, args.markdown)
        logger.info(f"Scan complete. Reports saved to {args.output} and {args.markdown}")
        print(f"[+] Scan complete. Reports saved to {args.output} and {args.markdown}")
    else:
        logger.info("No vulnerabilities found.")
        print("[-] No vulnerabilities found.")

if __name__ == "__main__":
    main()