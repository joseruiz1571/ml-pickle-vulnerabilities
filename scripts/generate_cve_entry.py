#!/usr/bin/env python3
"""
Generate CVE markdown entries from NVD JSON data.

This script takes JSON output from fetch_nvd.py and generates:
- Individual CVE markdown files using the repository template
- Updates to the vulnerability index

Usage:
    python generate_cve_entry.py --input cves.json --output-dir ./vulnerabilities
    python generate_cve_entry.py --input cves.json --output-dir ./vulnerabilities --update-index
    python generate_cve_entry.py --input cves.json --check-duplicates --vulnerabilities-dir ./vulnerabilities
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path


# Framework detection patterns (name -> keywords)
FRAMEWORK_PATTERNS = {
    'PyTorch': ['pytorch', 'torch.load', 'torch'],
    'Hugging Face': ['huggingface', 'hugging face', 'transformers', 'smolagents'],
    'TensorFlow': ['tensorflow', 'keras'],
    'MLflow': ['mlflow'],
    'scikit-learn': ['scikit-learn', 'sklearn', 'scikit learn'],
    'LangChain': ['langchain'],
    'LlamaIndex': ['llamaindex', 'llama_index', 'llama-index'],
    'Llama Stack': ['llama stack', 'llama-stack'],
    'ONNX': ['onnx'],
    'Ray': ['ray'],
    'Picklescan': ['picklescan'],
    'Safetensors': ['safetensors'],
}


def get_existing_cves(vulnerabilities_dir: Path) -> set:
    """Scan vulnerabilities directory for existing CVE IDs."""
    existing = set()
    if not vulnerabilities_dir.exists():
        return existing

    for file in vulnerabilities_dir.glob('CVE-*.md'):
        # Extract CVE ID from filename (e.g., CVE-2024-50050.md -> CVE-2024-50050)
        cve_id = file.stem
        existing.add(cve_id)

    return existing


def detect_framework(description: str) -> str:
    """Detect framework name from CVE description."""
    description_lower = description.lower()

    for framework, keywords in FRAMEWORK_PATTERNS.items():
        for keyword in keywords:
            if keyword.lower() in description_lower:
                return framework

    return "Unknown"


def get_severity_label(cvss_score) -> str:
    """Get severity label from CVSS score."""
    if cvss_score == "Unknown" or cvss_score is None:
        return "Unknown"

    try:
        score = float(cvss_score)
        if score >= 9.0:
            return "Critical"
        elif score >= 7.0:
            return "High"
        elif score >= 4.0:
            return "Medium"
        else:
            return "Low"
    except (ValueError, TypeError):
        return "Unknown"


def format_date(date_str: str) -> str:
    """Format date string to YYYY-MM-DD."""
    if not date_str or date_str == "Unknown":
        return datetime.now().strftime('%Y-%m-%d')

    # Handle various date formats
    try:
        # Try ISO format first (2024-10-15T12:00:00)
        dt = datetime.fromisoformat(date_str.replace('Z', '+00:00').split('+')[0].split('.')[0])
        return dt.strftime('%Y-%m-%d')
    except ValueError:
        pass

    # Return as-is if we can't parse it, truncated to date portion
    return date_str[:10] if len(date_str) >= 10 else date_str


def extract_year(cve_id: str) -> str:
    """Extract year from CVE ID (e.g., CVE-2024-50050 -> 2024)."""
    match = re.match(r'CVE-(\d{4})-\d+', cve_id)
    if match:
        return match.group(1)
    return str(datetime.now().year)


def generate_cve_markdown(cve_data: dict) -> str:
    """Generate CVE markdown content from NVD data."""
    cve_id = cve_data['id']
    description = cve_data.get('description', 'No description available')
    cvss_score = cve_data.get('cvss_score', 'Unknown')
    cvss_severity = cve_data.get('cvss_severity', get_severity_label(cvss_score))
    published = format_date(cve_data.get('published', ''))
    nvd_url = cve_data.get('nvd_url', f'https://nvd.nist.gov/vuln/detail/{cve_id}')

    framework = detect_framework(description)
    severity_label = get_severity_label(cvss_score)

    # Determine attack vector from description
    desc_lower = description.lower()
    if any(word in desc_lower for word in ['remote', 'network', 'unauthenticated', 'internet']):
        attack_vector = "Network"
    elif any(word in desc_lower for word in ['local', 'file', 'directory']):
        attack_vector = "Local"
    else:
        attack_vector = "Network"  # Default assumption for deserialization

    # Clean up description for markdown
    clean_description = description.replace('|', '\\|').replace('\n', ' ')

    markdown = f"""# {cve_id}: {framework} Deserialization Vulnerability

## Quick Reference

| Field | Value |
|-------|-------|
| **CVE ID** | {cve_id} |
| **Framework** | {framework} |
| **Affected Versions** | See vendor advisory |
| **Fixed Version** | See vendor advisory |
| **CVSS Score** | {cvss_score} ({severity_label}) |
| **CWE** | CWE-502 (Deserialization of Untrusted Data) |
| **Attack Vector** | {attack_vector} |
| **Disclosed** | {published} |

## Summary

{clean_description}

## Technical Details

**Vulnerable Function:** To be documented

**Root Cause:** Unsafe deserialization of untrusted data allowing arbitrary code execution.

**Attack Pattern:**
1. Attacker crafts malicious serialized payload
2. Payload is loaded by vulnerable function
3. Deserialization triggers code execution
4. Arbitrary code executes with application privileges

## Proof of Concept

See NVD entry and vendor advisory for technical details.

## Remediation

### Immediate Actions

1. **Check if affected**: Review your dependencies for vulnerable versions
2. **Upgrade**: Apply vendor patches when available
3. **Audit**: Review code for usage of vulnerable functions

### Long-term Mitigations

- Use safe serialization formats (safetensors, JSON) instead of pickle
- Implement input validation and source verification
- Never deserialize data from untrusted sources

## GRC Implications

### Risk Assessment

**Risk Level:** {severity_label}

**Impact Scenarios:**
- Remote code execution on systems processing untrusted data
- Supply chain compromise through malicious model files
- Data exfiltration or system compromise

### Vendor Assessment Questions

1. "Do you use {framework} for model serialization?"
2. "What version of {framework} is deployed in production?"
3. "Are models loaded from untrusted or external sources?"
4. "What controls exist to validate model file integrity?"

### Control Recommendations

| Control | Description | Priority |
|---------|-------------|----------|
| Version upgrade | Apply security patches | {severity_label} |
| Input validation | Verify model sources | High |
| Monitoring | Log model loading operations | Medium |

## References

- [NVD Entry]({nvd_url})
- Search for GitHub Advisory: https://github.com/advisories?query={cve_id}

## Timeline

| Date | Event |
|------|-------|
| {published} | Published to NVD |

## Related Vulnerabilities

*To be documented*

---

*Last updated: {datetime.now().strftime('%Y-%m-%d')}*

*Tags: `{framework.lower().replace(' ', '-')}` `deserialization` `{severity_label.lower()}` `rce` `pickle`*
"""

    return markdown


def filter_duplicates(cves: list, existing_ids: set) -> tuple:
    """Filter out CVEs that already exist."""
    new_cves = []
    duplicates = []

    for cve in cves:
        cve_id = cve['id']
        if cve_id in existing_ids:
            duplicates.append(cve_id)
        else:
            new_cves.append(cve)

    return new_cves, duplicates


def filter_by_severity(cves: list, min_cvss: float = 7.0) -> tuple:
    """Split CVEs into high severity (>= min_cvss) and lower."""
    high_severity = []
    lower_severity = []

    for cve in cves:
        cvss = cve.get('cvss_score')
        try:
            if cvss and cvss != "Unknown" and float(cvss) >= min_cvss:
                high_severity.append(cve)
            else:
                lower_severity.append(cve)
        except (ValueError, TypeError):
            lower_severity.append(cve)

    return high_severity, lower_severity


def update_index_md(index_path: Path, new_cves: list) -> str:
    """Update index.md with new CVE entries. Returns updated content."""
    if not index_path.exists():
        print(f"Warning: Index file not found at {index_path}", file=sys.stderr)
        return ""

    content = index_path.read_text()

    for cve in new_cves:
        cve_id = cve['id']
        cvss_score = cve.get('cvss_score', 'Unknown')
        description = cve.get('description', 'No description')
        framework = detect_framework(description)
        severity = get_severity_label(cvss_score)
        year = extract_year(cve_id)

        # Short summary for table
        short_desc = description[:50] + '...' if len(description) > 50 else description
        short_desc = short_desc.replace('|', '-').replace('\n', ' ')

        # Entry for severity table
        severity_entry = f"| [{cve_id}]({cve_id}.md) | {framework} | {cvss_score} | {short_desc} |"

        # Entry for framework section
        framework_entry = f"- [{cve_id}]({cve_id}.md) - {short_desc}"

        # Entry for year section
        year_entry = f"- [{cve_id}]({cve_id}.md) - {framework}"

        # Insert into severity section
        if severity == "Critical":
            marker = "### Critical (CVSS 9.0+)"
            # Find the table after this marker and insert
            content = insert_after_table_header(content, marker, severity_entry)
        elif severity == "High":
            marker = "### High (CVSS 7.0-8.9)"
            content = insert_after_table_header(content, marker, severity_entry)

        # Insert into framework section
        framework_marker = f"### {framework}"
        if framework_marker in content:
            # Insert after the framework header
            content = insert_after_marker(content, framework_marker, framework_entry)

        # Insert into year section
        year_marker = f"### {year}"
        if year_marker in content:
            content = insert_after_marker(content, year_marker, year_entry)

    # Update statistics
    content = update_statistics(content, len(new_cves))

    return content


def insert_after_table_header(content: str, marker: str, entry: str) -> str:
    """Insert entry after a table header row following the marker."""
    if marker not in content:
        return content

    lines = content.split('\n')
    result = []
    found_marker = False
    found_table_header = False
    inserted = False

    for i, line in enumerate(lines):
        result.append(line)

        if marker in line:
            found_marker = True
            continue

        if found_marker and not found_table_header:
            if line.startswith('|---'):
                found_table_header = True
                continue

        if found_marker and found_table_header and not inserted:
            # Insert after the separator row
            if line.startswith('|'):
                # There's existing content, insert before it
                result.insert(len(result) - 1, entry)
            else:
                # Empty table, just add the entry
                result.insert(len(result) - 1, entry)
            inserted = True

    return '\n'.join(result)


def insert_after_marker(content: str, marker: str, entry: str) -> str:
    """Insert entry after a marker line."""
    if marker not in content:
        return content

    lines = content.split('\n')
    result = []

    for i, line in enumerate(lines):
        result.append(line)
        if marker in line:
            result.append(entry)

    return '\n'.join(result)


def update_statistics(content: str, added_count: int) -> str:
    """Update the statistics section."""
    # Update total count
    match = re.search(r'\| Total CVEs tracked \| (\d+)', content)
    if match:
        old_count = int(match.group(1))
        new_count = old_count + added_count
        content = content.replace(
            f'| Total CVEs tracked | {old_count}',
            f'| Total CVEs tracked | {new_count}'
        )

    # Update last updated date
    today = datetime.now().strftime('%Y-%m-%d')
    content = re.sub(
        r'\| Last updated \| [\d-]+ \|',
        f'| Last updated | {today} |',
        content
    )

    return content


def main():
    parser = argparse.ArgumentParser(
        description='Generate CVE markdown entries from NVD JSON data'
    )
    parser.add_argument(
        '--input',
        type=str,
        required=True,
        help='Path to JSON file from fetch_nvd.py'
    )
    parser.add_argument(
        '--output-dir',
        type=str,
        help='Directory to write CVE markdown files'
    )
    parser.add_argument(
        '--vulnerabilities-dir',
        type=str,
        default='vulnerabilities',
        help='Directory containing existing CVE files (for deduplication)'
    )
    parser.add_argument(
        '--update-index',
        action='store_true',
        help='Also update index.md'
    )
    parser.add_argument(
        '--check-duplicates',
        action='store_true',
        help='Only check for duplicates, output JSON with new CVEs'
    )
    parser.add_argument(
        '--min-cvss',
        type=float,
        default=7.0,
        help='Minimum CVSS score to process (default: 7.0)'
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Preview what would be generated without writing files'
    )

    args = parser.parse_args()

    # Load input JSON
    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Error: Input file not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    with open(input_path) as f:
        cves = json.load(f)

    print(f"Loaded {len(cves)} CVEs from input", file=sys.stderr)

    # Get existing CVEs for deduplication
    vuln_dir = Path(args.vulnerabilities_dir)
    existing_ids = get_existing_cves(vuln_dir)
    print(f"Found {len(existing_ids)} existing CVE entries", file=sys.stderr)

    # Filter duplicates
    new_cves, duplicates = filter_duplicates(cves, existing_ids)
    print(f"After deduplication: {len(new_cves)} new, {len(duplicates)} duplicates", file=sys.stderr)

    if duplicates:
        print(f"Skipped duplicates: {', '.join(duplicates)}", file=sys.stderr)

    # If just checking duplicates, output JSON and exit
    if args.check_duplicates:
        result = {
            'new_cves': new_cves,
            'duplicates': duplicates,
            'total_input': len(cves),
            'total_new': len(new_cves)
        }
        print(json.dumps(result, indent=2))
        return

    # Filter by severity
    high_severity, lower_severity = filter_by_severity(new_cves, args.min_cvss)
    print(f"High/Critical severity (CVSS >= {args.min_cvss}): {len(high_severity)}", file=sys.stderr)
    print(f"Lower severity: {len(lower_severity)}", file=sys.stderr)

    if not high_severity:
        print("No high/critical severity CVEs to process", file=sys.stderr)
        # Output summary for workflow
        result = {
            'generated_files': [],
            'critical_count': 0,
            'high_count': 0
        }
        print(json.dumps(result))
        return

    # Determine output directory
    output_dir = Path(args.output_dir) if args.output_dir else vuln_dir

    # Generate CVE files
    generated_files = []
    critical_count = 0
    high_count = 0

    for cve in high_severity:
        cve_id = cve['id']
        cvss = cve.get('cvss_score', 0)

        try:
            score = float(cvss) if cvss and cvss != "Unknown" else 0
            if score >= 9.0:
                critical_count += 1
            else:
                high_count += 1
        except (ValueError, TypeError):
            high_count += 1

        markdown = generate_cve_markdown(cve)
        output_file = output_dir / f"{cve_id}.md"

        if args.dry_run:
            print(f"[DRY RUN] Would create: {output_file}", file=sys.stderr)
            print(f"--- Content preview for {cve_id} ---", file=sys.stderr)
            print(markdown[:500] + "...", file=sys.stderr)
        else:
            output_file.write_text(markdown)
            print(f"Created: {output_file}", file=sys.stderr)

        generated_files.append(str(output_file))

    # Update index if requested
    if args.update_index and high_severity:
        index_path = vuln_dir / 'index.md'
        updated_content = update_index_md(index_path, high_severity)

        if updated_content:
            if args.dry_run:
                print(f"[DRY RUN] Would update: {index_path}", file=sys.stderr)
            else:
                index_path.write_text(updated_content)
                print(f"Updated: {index_path}", file=sys.stderr)

    # Output summary for workflow consumption
    result = {
        'generated_files': generated_files,
        'critical_count': critical_count,
        'high_count': high_count
    }
    print(json.dumps(result))


if __name__ == '__main__':
    main()
