# ML Pickle Vulnerability Tracker

A curated knowledge base tracking pickle deserialization vulnerabilities in machine learning frameworks. Designed for GRC professionals, security teams, and anyone evaluating ML system security.

## Why This Exists

Pickle deserialization is the #1 security risk in ML model loading. Unlike traditional software vulnerabilities, these affect anyone who:
- Downloads models from Hugging Face Hub
- Loads pre-trained models in PyTorch/TensorFlow
- Uses MLflow for model management
- Accepts model files from external sources

This tracker provides actionable intelligence for security assessments, vendor evaluations, and policy development.

---

## Quick Reference: Critical Vulnerabilities

| CVE | Framework | CVSS | Summary | Fixed In |
|-----|-----------|------|---------|----------|
| [CVE-2025-14931](vulnerabilities/CVE-2025-14931.md) | smolagents | **10.0** | Remote Python Executor RCE (0-day) | Pending |
| [CVE-2024-50050](vulnerabilities/CVE-2024-50050.md) | Llama Stack | 9.8 | ZeroMQ pickle deserialization | 0.0.41 |
| [CVE-2025-68664](vulnerabilities/CVE-2025-68664.md) | LangChain | 9.3 | Serialization injection "LangGrinch" | 0.3.81, 1.2.5 |
| [CVE-2025-32434](vulnerabilities/CVE-2025-32434.md) | PyTorch | 9.3 | `torch.load` RCE even with `weights_only=True` | 2.6.0 |
| [CVE-2024-37059](vulnerabilities/CVE-2024-37059.md) | MLflow | 8.8 | PyTorch model loading via pickle | 2.14.2 |
| [CVE-2024-14021](vulnerabilities/CVE-2024-14021.md) | LlamaIndex | 8.4 | BGEM3Index unsafe deserialization | > 0.11.6 |
| [CVE-2023-6730](vulnerabilities/CVE-2023-6730.md) | Transformers | 7.8 | RagRetriever pickle loading | 4.36.0 |
| [CVE-2025-1716](vulnerabilities/CVE-2025-1716.md) | Picklescan | 7.5 | Scanner bypass via deserialization | 0.0.23 |

**[View all vulnerabilities →](vulnerabilities/index.md)**

---

## Framework Coverage

| Framework | Vulnerabilities Tracked | Latest Issue | Status |
|-----------|------------------------|--------------|--------|
| [PyTorch](frameworks/pytorch.md) | 5+ | Apr 2025 | Active |
| [Hugging Face Transformers](frameworks/huggingface.md) | 6+ | Nov 2024 | Active |
| [MLflow](frameworks/mlflow.md) | 9 | Jun 2024 | Active |
| [TensorFlow/Keras](frameworks/tensorflow.md) | 3+ | 2024 | Monitoring |
| [scikit-learn](frameworks/scikit-learn.md) | 2+ | 2024 | Monitoring |

---

## For GRC Professionals

### Vendor Assessment Questions

Use these during AI/ML vendor security reviews:

**Model Loading:**
- "How do you serialize and deserialize ML models?"
- "Do you use pickle, joblib, or safer alternatives like safetensors?"
- "What PyTorch/TensorFlow version do you use?"

**Supply Chain:**
- "Do you load models from external sources (Hugging Face Hub, user uploads)?"
- "How do you validate model file integrity before loading?"
- "Do you scan model files for malicious payloads?"

**[Full question bank →](analysis/vendor-assessment-questions.md)**

### Control Recommendations

| Risk | Control | Implementation |
|------|---------|----------------|
| Malicious model files | Use safetensors format | Migrate from .pkl/.pt to .safetensors |
| Untrusted model sources | Model provenance verification | Implement allowlists for model sources |
| Version vulnerabilities | Dependency scanning | Add ML frameworks to vulnerability scanning |

**[Remediation patterns →](analysis/remediation-patterns.md)**

---

## Statistics

- **Total CVEs Tracked:** 8 documented (25+ planned)
- **Frameworks Covered:** 8
- **Critical Severity (CVSS 9+):** 4
- **High Severity (CVSS 7-8.9):** 4
- **Last Updated:** January 2026

---

## Data Sources

This tracker aggregates information from:
- [NIST National Vulnerability Database (NVD)](https://nvd.nist.gov/)
- [GitHub Advisory Database](https://github.com/advisories)
- [OSV (Open Source Vulnerabilities)](https://osv.dev/)
- [Protect AI huntr](https://huntr.com/) - AI/ML bug bounty platform
- Framework security advisories

---

## Contributing

Found a pickle-related vulnerability not listed here? See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## About

Created by [Jose Ruiz-Vazquez](https://github.com/joseruiz1571), a GRC professional building practical security resources for AI governance.

Related project: [ML Security Lab](https://github.com/joseruiz1571/ml-security-lab) - Hands-on exercises for ML security scanning.

---

## License

This project is licensed under CC BY 4.0. You are free to share and adapt this material with attribution.
