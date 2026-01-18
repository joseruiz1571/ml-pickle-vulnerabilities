#!/usr/bin/env python3
"""
Fetch pickle-related CVEs from the NIST National Vulnerability Database.

This script queries the NVD API for new CVEs matching pickle deserialization
patterns in ML frameworks. Run manually or via GitHub Actions.

Usage:
    python fetch_nvd.py                    # Check last 7 days
    python fetch_nvd.py --days 30          # Check last 30 days
    python fetch_nvd.py --output issues    # Output as GitHub issue format
"""

import argparse
import json
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path

try:
    import nvdlib
except ImportError:
    print("Error: nvdlib not installed. Run: pip install nvdlib")
    sys.exit(1)


# Keywords to search for
PICKLE_KEYWORDS = [
    'pickle',
    'deserialization',
    'deserialize',
    'torch.load',
    'joblib',
    'cloudpickle',
    'dill',
    'marshal',
    'shelve',
]

# ML frameworks to monitor
FRAMEWORK_KEYWORDS = [
    'pytorch',
    'torch',
    'tensorflow',
    'keras',
    'huggingface',
    'transformers',
    'mlflow',
    'scikit-learn',
    'sklearn',
    'onnx',
    'ray',
    'llama',
    'safetensors',
    'picklescan',
]

# Combine for comprehensive search
ALL_KEYWORDS = list(set(PICKLE_KEYWORDS + FRAMEWORK_KEYWORDS))


def fetch_cves(days_back: int = 7, api_key: str = None) -> list:
    """Fetch CVEs from NVD matching our keywords."""
    end_date = datetime.now()
    start_date = end_date - timedelta(days=days_back)

    all_cves = []
    seen_ids = set()

    for keyword in ALL_KEYWORDS:
        try:
            print(f"Searching for: {keyword}...", file=sys.stderr)

            if api_key:
                cves = nvdlib.searchCVE(
                    keywordSearch=keyword,
                    pubStartDate=start_date,
                    pubEndDate=end_date,
                    key=api_key
                )
            else:
                cves = nvdlib.searchCVE(
                    keywordSearch=keyword,
                    pubStartDate=start_date,
                    pubEndDate=end_date
                )

            for cve in cves:
                if cve.id not in seen_ids:
                    seen_ids.add(cve.id)
                    all_cves.append(cve)

        except Exception as e:
            print(f"Warning: Error searching for '{keyword}': {e}", file=sys.stderr)

    return all_cves


def filter_relevant_cves(cves: list) -> list:
    """Filter CVEs to only those likely related to pickle deserialization."""
    relevant = []

    # Keywords that indicate pickle/deserialization relevance
    relevance_indicators = [
        'pickle', 'deserializ', 'untrusted data', 'arbitrary code',
        'remote code execution', 'rce', 'torch.load', 'model load',
        'cwe-502', 'unsafe', 'malicious'
    ]

    for cve in cves:
        try:
            description = cve.descriptions[0].value.lower()

            # Check if description contains relevance indicators
            if any(indicator in description for indicator in relevance_indicators):
                relevant.append(cve)
        except (IndexError, AttributeError):
            continue

    return relevant


def format_cve_summary(cve) -> dict:
    """Format a CVE into a summary dictionary."""
    try:
        description = cve.descriptions[0].value
    except (IndexError, AttributeError):
        description = "No description available"

    try:
        cvss_score = cve.score[1] if cve.score else "Unknown"
        cvss_severity = cve.score[2] if cve.score else "Unknown"
    except (IndexError, AttributeError, TypeError):
        cvss_score = "Unknown"
        cvss_severity = "Unknown"

    return {
        'id': cve.id,
        'description': description[:500] + '...' if len(description) > 500 else description,
        'cvss_score': cvss_score,
        'cvss_severity': cvss_severity,
        'published': str(cve.published) if hasattr(cve, 'published') else "Unknown",
        'nvd_url': f"https://nvd.nist.gov/vuln/detail/{cve.id}"
    }


def output_as_json(cves: list):
    """Output CVEs as JSON."""
    summaries = [format_cve_summary(cve) for cve in cves]
    print(json.dumps(summaries, indent=2))


def output_as_markdown(cves: list):
    """Output CVEs as Markdown table."""
    print("# New Pickle-Related CVEs\n")
    print(f"*Scanned: {datetime.now().strftime('%Y-%m-%d %H:%M')}*\n")

    if not cves:
        print("No new CVEs found matching pickle/deserialization criteria.\n")
        return

    print("| CVE ID | CVSS | Summary |")
    print("|--------|------|---------|")

    for cve in cves:
        summary = format_cve_summary(cve)
        short_desc = summary['description'][:100] + '...' if len(summary['description']) > 100 else summary['description']
        print(f"| [{summary['id']}]({summary['nvd_url']}) | {summary['cvss_score']} | {short_desc} |")


def output_as_github_issue(cves: list):
    """Output CVEs as GitHub issue format for automation."""
    for cve in cves:
        summary = format_cve_summary(cve)
        print(f"---NEW_CVE_START---")
        print(f"title: New CVE to review: {summary['id']}")
        print(f"labels: needs-review,automated")
        print(f"body: |")
        print(f"  ## {summary['id']}")
        print(f"  ")
        print(f"  **CVSS Score:** {summary['cvss_score']} ({summary['cvss_severity']})")
        print(f"  ")
        print(f"  **Published:** {summary['published']}")
        print(f"  ")
        print(f"  ### Description")
        print(f"  {summary['description']}")
        print(f"  ")
        print(f"  ### Links")
        print(f"  - [NVD Entry]({summary['nvd_url']})")
        print(f"  ")
        print(f"  ### Action Required")
        print(f"  - [ ] Review if this CVE is relevant to pickle deserialization in ML")
        print(f"  - [ ] If relevant, create entry using template")
        print(f"  - [ ] Update vulnerability index")
        print(f"---NEW_CVE_END---")


def main():
    parser = argparse.ArgumentParser(
        description='Fetch pickle-related CVEs from NVD'
    )
    parser.add_argument(
        '--days',
        type=int,
        default=7,
        help='Number of days to look back (default: 7)'
    )
    parser.add_argument(
        '--output',
        choices=['json', 'markdown', 'issues'],
        default='markdown',
        help='Output format (default: markdown)'
    )
    parser.add_argument(
        '--all',
        action='store_true',
        help='Show all CVEs, not just filtered relevant ones'
    )

    args = parser.parse_args()

    # Get API key from environment
    api_key = os.getenv('NVD_API_KEY')
    if not api_key:
        print("Note: No NVD_API_KEY set. Rate limiting will be stricter.", file=sys.stderr)

    # Fetch CVEs
    print(f"Fetching CVEs from last {args.days} days...", file=sys.stderr)
    cves = fetch_cves(days_back=args.days, api_key=api_key)
    print(f"Found {len(cves)} total CVEs matching keywords", file=sys.stderr)

    # Filter to relevant ones
    if not args.all:
        cves = filter_relevant_cves(cves)
        print(f"Filtered to {len(cves)} likely relevant CVEs", file=sys.stderr)

    # Output
    if args.output == 'json':
        output_as_json(cves)
    elif args.output == 'issues':
        output_as_github_issue(cves)
    else:
        output_as_markdown(cves)


if __name__ == '__main__':
    main()
