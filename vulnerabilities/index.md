# Vulnerability Index

All tracked pickle deserialization vulnerabilities in ML frameworks.

## By Severity

### Critical (CVSS 9.0+)

| CVE | Framework | CVSS | Summary |
|-----|-----------|------|---------|
| [CVE-2026-25632](CVE-2026-25632.md) | Unknown | 10.0 | EPyT-Flow is a Python package designed for the eas... |
| [CVE-2026-21531](CVE-2026-21531.md) | Unknown | 9.8 | Deserialization of untrusted data in Azure SDK all... |
| [CVE-2026-26215](CVE-2026-26215.md) | Unknown | 9.3 | manga-image-translator version beta-0.3 and prior ... |
| [CVE-2025-14931](CVE-2025-14931.md) | smolagents | 10.0 | Remote Python Executor RCE (0-day) |
| [CVE-2024-50050](CVE-2024-50050.md) | Llama Stack | 9.8 | ZeroMQ pickle deserialization RCE |
| [CVE-2025-68664](CVE-2025-68664.md) | LangChain | 9.3 | Serialization injection "LangGrinch" |
| [CVE-2025-32434](CVE-2025-32434.md) | PyTorch | 9.3 | torch.load RCE with weights_only=True |

### High (CVSS 7.0-8.9)

| CVE | Framework | CVSS | Summary |
|-----|-----------|------|---------|
| [CVE-2026-1669](CVE-2026-1669.md) | TensorFlow | 7.1 | Arbitrary file read in the model loading mechanism... |
| [CVE-2026-0910](CVE-2026-0910.md) | Ray | 8.8 | The wpForo Forum plugin for WordPress is vulnerabl... |
| [CVE-2026-21511](CVE-2026-21511.md) | Unknown | 7.5 | Deserialization of untrusted data in Microsoft Off... |
| [CVE-2026-25923](CVE-2026-25923.md) | Unknown | 8.7 | my little forum is a PHP and MySQL based internet ... |
| [CVE-2024-37059](CVE-2024-37059.md) | MLflow | 8.8 | PyTorch model loading via pickle |
| [CVE-2024-14021](CVE-2024-14021.md) | LlamaIndex | 8.4 | BGEM3Index unsafe deserialization |
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

### Hugging Face
- [CVE-2025-14931](CVE-2025-14931.md) - smolagents Remote Python Executor (CVSS 10.0)
- [CVE-2023-6730](CVE-2023-6730.md) - Transformers RagRetriever pickle loading
- CVE-2023-7018 - TransfoXLTokenizer (to be added)
- CVE-2024-3568 - TFPreTrainedModel (to be added)
- CVE-2024-11393 - MaskFormer parsing (to be added)

### LangChain
- [CVE-2025-68664](CVE-2025-68664.md) - Serialization injection "LangGrinch"
- CVE-2025-68665 - LangChain.js similar issue (to be added)

### LlamaIndex
- [CVE-2024-14021](CVE-2024-14021.md) - BGEM3Index unsafe deserialization

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
- [CVE-2025-14931](CVE-2025-14931.md) - smolagents (December, 0-day)
- [CVE-2025-68664](CVE-2025-68664.md) - LangChain (December)
- [CVE-2025-32434](CVE-2025-32434.md) - PyTorch (April)
- [CVE-2025-1716](CVE-2025-1716.md) - Picklescan (January)

### 2024
- [CVE-2024-50050](CVE-2024-50050.md) - Llama Stack (October)
- [CVE-2024-37059](CVE-2024-37059.md) - MLflow (June)
- [CVE-2024-14021](CVE-2024-14021.md) - LlamaIndex
- CVE-2024-37052 through CVE-2024-37060 - MLflow series (June)
- CVE-2024-3568 - Transformers (2024)
- CVE-2024-11393 - Transformers (November)

### 2023
- [CVE-2023-6730](CVE-2023-6730.md) - Transformers (December)
- CVE-2023-7018 - Transformers (December)

---

## By Attack Vector

### Network-Accessible (highest risk)
- [CVE-2025-14931](CVE-2025-14931.md) - smolagents Remote Python Executor (no auth)
- [CVE-2024-50050](CVE-2024-50050.md) - Llama Stack ZeroMQ
- [CVE-2025-68664](CVE-2025-68664.md) - LangChain via prompt injection
- [CVE-2025-32434](CVE-2025-32434.md) - Malicious model from Hub
- [CVE-2023-6730](CVE-2023-6730.md) - Remote index loading

### Local File
- [CVE-2024-37059](CVE-2024-37059.md) - Malicious model artifact
- [CVE-2024-14021](CVE-2024-14021.md) - LlamaIndex persist directory
- [CVE-2025-1716](CVE-2025-1716.md) - File analyzed by scanner

---

## Statistics

| Metric | Count |
|--------|-------|
| Total CVEs tracked | 15 (25+ planned) |
| Critical severity | 4 |
| High severity | 4 |
| Frameworks covered | 8 |
| Last updated | 2026-02-12 |

---

*To add a new vulnerability, see [CONTRIBUTING.md](../CONTRIBUTING.md)*
