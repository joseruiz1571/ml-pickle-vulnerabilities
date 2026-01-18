# Vulnerability Index

All tracked pickle deserialization vulnerabilities in ML frameworks.

## By Severity

### Critical (CVSS 9.0+)

| CVE | Framework | CVSS | Summary |
|-----|-----------|------|---------|
| [CVE-2024-50050](CVE-2024-50050.md) | Llama Stack | 9.8 | ZeroMQ pickle deserialization RCE |
| [CVE-2025-32434](CVE-2025-32434.md) | PyTorch | 9.3 | torch.load RCE with weights_only=True |

### High (CVSS 7.0-8.9)

| CVE | Framework | CVSS | Summary |
|-----|-----------|------|---------|
| [CVE-2024-37059](CVE-2024-37059.md) | MLflow | 8.8 | PyTorch model loading via pickle |
| [CVE-2023-6730](CVE-2023-6730.md) | Transformers | 7.8 | RagRetriever pickle loading |
| [CVE-2025-1716](CVE-2025-1716.md) | Picklescan | 7.5 | Scanner bypass via deserialization |

### Medium (CVSS 4.0-6.9)

*No entries yet*

### Low (CVSS < 4.0)

*No entries yet*

---

## By Framework

### PyTorch
- [CVE-2025-32434](CVE-2025-32434.md) - torch.load RCE with weights_only=True

### Hugging Face Transformers
- [CVE-2023-6730](CVE-2023-6730.md) - RagRetriever pickle loading
- CVE-2023-7018 - TransfoXLTokenizer (to be added)
- CVE-2024-3568 - TFPreTrainedModel (to be added)
- CVE-2024-11393 - MaskFormer parsing (to be added)

### MLflow
- [CVE-2024-37059](CVE-2024-37059.md) - PyTorch model loading
- CVE-2024-37052 - scikit-learn model loading (to be added)
- CVE-2024-37054 - PyFunc model loading (to be added)
- CVE-2024-37056 - LightGBM model loading (to be added)
- CVE-2024-37057 - TensorFlow model loading (to be added)
- CVE-2024-37060 - Recipes (to be added)

### Meta Llama Stack
- [CVE-2024-50050](CVE-2024-50050.md) - ZeroMQ pickle deserialization

### Security Tools
- [CVE-2025-1716](CVE-2025-1716.md) - Picklescan scanner bypass
- CVE-2025-1889 - Picklescan hidden file bypass (to be added)
- CVE-2025-1944 - Picklescan ZIP tampering (to be added)
- CVE-2025-1945 - Picklescan ZIP flag bypass (to be added)

---

## By Year

### 2025
- [CVE-2025-32434](CVE-2025-32434.md) - PyTorch (April)
- [CVE-2025-1716](CVE-2025-1716.md) - Picklescan (January)

### 2024
- [CVE-2024-50050](CVE-2024-50050.md) - Llama Stack (October)
- [CVE-2024-37059](CVE-2024-37059.md) - MLflow (June)
- CVE-2024-37052 through CVE-2024-37060 - MLflow series (June)
- CVE-2024-3568 - Transformers (2024)
- CVE-2024-11393 - Transformers (November)

### 2023
- [CVE-2023-6730](CVE-2023-6730.md) - Transformers (December)
- CVE-2023-7018 - Transformers (December)

---

## By Attack Vector

### Network-Accessible (highest risk)
- [CVE-2024-50050](CVE-2024-50050.md) - Llama Stack ZeroMQ
- [CVE-2025-32434](CVE-2025-32434.md) - Malicious model from Hub
- [CVE-2023-6730](CVE-2023-6730.md) - Remote index loading

### Local File
- [CVE-2024-37059](CVE-2024-37059.md) - Malicious model artifact
- [CVE-2025-1716](CVE-2025-1716.md) - File analyzed by scanner

---

## Statistics

| Metric | Count |
|--------|-------|
| Total CVEs tracked | 5 (25+ planned) |
| Critical severity | 2 |
| High severity | 3 |
| Frameworks covered | 5 |
| Last updated | 2026-01-18 |

---

*To add a new vulnerability, see [CONTRIBUTING.md](../CONTRIBUTING.md)*
