# PyTorch Pickle Vulnerabilities

## Overview

PyTorch is the most widely-used deep learning framework, with `torch.load()` being the primary method for loading saved models. Unfortunately, `torch.load()` uses Python's pickle module by default, making it a major attack surface.

**Minimum Safe Version:** 2.6.0 (fixes CVE-2025-32434)

---

## Key Vulnerability

### CVE-2025-32434: torch.load RCE with weights_only=True

**Severity:** Critical (CVSS 9.3)

The `weights_only=True` flag was introduced as a security measure but was bypassed through legacy tar file handling. Even "safe" model loading could result in code execution.

**Impact:** Any application loading untrusted .pt files is vulnerable, even with security flags enabled.

[Full details →](../vulnerabilities/CVE-2025-32434.md)

---

## Vulnerable Patterns

### Pattern 1: Basic torch.load (Always Unsafe)

```python
# VULNERABLE - arbitrary code execution
import torch
model = torch.load("model.pt")
```

### Pattern 2: weights_only=True (Unsafe before 2.6.0)

```python
# VULNERABLE in PyTorch < 2.6.0
import torch
model = torch.load("model.pt", weights_only=True)
```

### Pattern 3: Loading from URLs (Supply Chain Risk)

```python
# VULNERABLE - model source not validated
import torch
model = torch.hub.load("someuser/repo", "model_name")
```

---

## Secure Alternatives

### Option 1: Safetensors (Recommended)

```python
from safetensors.torch import load_file, save_file

# Save
save_file(model.state_dict(), "model.safetensors")

# Load
state_dict = load_file("model.safetensors")
model.load_state_dict(state_dict)
```

### Option 2: TorchScript (torch.jit)

```python
# Save
scripted_model = torch.jit.script(model)
scripted_model.save("model_scripted.pt")

# Load (safer, but not immune to all attacks)
model = torch.jit.load("model_scripted.pt")
```

### Option 3: torch.load with Validation (PyTorch 2.6.0+)

```python
import torch

# Only in PyTorch >= 2.6.0
model = torch.load(
    "model.pt",
    weights_only=True,  # Now actually enforced
    map_location="cpu"  # Avoid GPU-specific exploits
)
```

---

## Version History

| Version | Security Status | Notes |
|---------|-----------------|-------|
| < 2.6.0 | Vulnerable | weights_only=True bypassed (CVE-2025-32434) |
| 2.6.0+ | Fixed | Legacy tar path blocked when weights_only=True |

---

## Detection

### Check PyTorch Version

```bash
python -c "import torch; print(torch.__version__)"
```

### Find Vulnerable Code Patterns

```bash
# Using grep
grep -rn "torch.load" --include="*.py" .

# Using semgrep (custom rule)
semgrep --config path/to/pytorch-rules.yaml .
```

### Semgrep Rule

```yaml
rules:
  - id: unsafe-torch-load
    patterns:
      - pattern: torch.load(...)
      - pattern-not: torch.load(..., weights_only=True, ...)
    message: "torch.load without weights_only=True can execute arbitrary code"
    severity: ERROR
    languages: [python]
```

---

## Related CVEs

| CVE | Status | Description |
|-----|--------|-------------|
| [CVE-2025-32434](../vulnerabilities/CVE-2025-32434.md) | Fixed in 2.6.0 | weights_only bypass |
| Historical | Ongoing | torch.load has always used pickle |

---

## GRC Implications

### Risk Assessment Questions

1. "What version of PyTorch do you use?"
2. "Do you load models from external sources?"
3. "Have you migrated to safetensors?"
4. "Do you use torch.hub.load()?"

### Control Recommendations

| Control | Priority | Effort |
|---------|----------|--------|
| Upgrade to PyTorch >= 2.6.0 | Critical | Low |
| Migrate to safetensors | High | Medium |
| Implement model source allowlists | High | Medium |
| Add pickle scanning to CI/CD | Medium | Low |

---

## References

- [PyTorch Security Advisories](https://github.com/pytorch/pytorch/security/advisories)
- [PyTorch Serialization Docs](https://pytorch.org/docs/stable/notes/serialization.html)
- [Safetensors Documentation](https://huggingface.co/docs/safetensors/)

---

*Last updated: 2026-01-18*
