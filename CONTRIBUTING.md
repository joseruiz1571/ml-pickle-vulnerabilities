# Contributing to ML Pickle Vulnerability Tracker

Thank you for helping build this resource for the security community.

## Ways to Contribute

### 1. Report a Missing CVE

If you find a pickle-related vulnerability not listed here:

1. Check the [vulnerability index](vulnerabilities/index.md) to confirm it's not already tracked
2. Open an issue with:
   - CVE ID
   - Affected framework
   - Link to advisory or disclosure

### 2. Add a New CVE Entry

1. Copy the [template](templates/vulnerability-template.md)
2. Fill in all sections (it's okay to leave some as "Unknown" if not public)
3. Save as `vulnerabilities/CVE-YYYY-XXXXX.md`
4. Update `vulnerabilities/index.md`
5. Update the relevant framework file in `frameworks/`
6. Submit a pull request

### 3. Improve Existing Entries

- Fix errors or outdated information
- Add references
- Expand GRC implications
- Add remediation details

### 4. Add Framework Coverage

Create a new framework summary following the pattern in `frameworks/pytorch.md`:
- Overview of pickle usage in the framework
- Known vulnerabilities
- Secure alternatives
- Detection methods

---

## Quality Guidelines

### For Vulnerability Entries

**Required fields:**
- CVE ID
- Framework and affected versions
- Fixed version
- Summary (plain English)
- At least one reference

**Preferred:**
- CVSS score
- Technical root cause
- Remediation steps
- GRC implications

### For GRC Content

The vendor assessment questions and control recommendations should be:
- **Actionable** - Can be directly used in an assessment
- **Specific** - References exact versions, functions, configurations
- **Practical** - Appropriate for a non-technical audience to ask

---

## Style Guide

### Tone
- Professional but accessible
- Focus on practical implications
- Avoid unnecessary jargon

### Formatting
- Use tables for structured data
- Use code blocks for commands and code
- Include severity ratings consistently

### Tags
Use consistent tags at the end of each CVE entry:
- Framework: `pytorch`, `tensorflow`, `huggingface`, `mlflow`, etc.
- Function: `torch.load`, `pickle.load`, etc.
- Severity: `critical`, `high`, `medium`, `low`
- Attack type: `rce`, `model-loading`, `network`, `supply-chain`

---

## Code of Conduct

- Be respectful and constructive
- Focus on facts, not speculation
- Credit original researchers and disclosers
- Don't include working exploit code (describe patterns instead)

---

## Questions?

Open an issue or reach out to [@joseruiz1571](https://github.com/joseruiz1571).
