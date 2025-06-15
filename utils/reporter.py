import json
import os
from utils.logger import logger

def generate_json_report(results, output_file):
    try:
        with open(output_file, "w") as f:
            json.dump(results, f, indent=4)
        logger.info(f"JSON report saved to {output_file}")
    except Exception as e:
        logger.error(f"Error generating JSON report: {e}")

def generate_markdown_report(results, output_file):
    try:
        with open(output_file, "w") as f:
            f.write("# Zerox Scan Report\n\n")
            for result in results:
                f.write(f"## {result['vulnerability']}\n")
                f.write(f"- **URL**: {result['url']}\n")
                f.write(f"- **Severity**: {result['severity']}\n")
                f.write(f"- **Details**: {result['details']}\n")
                if "payload" in result:
                    f.write(f"- **Payload**: {result['payload']}\n")
                f.write("\n")
        logger.info(f"Markdown report saved to {output_file}")
    except Exception as e:
        logger.error(f"Error generating Markdown report: {e}")