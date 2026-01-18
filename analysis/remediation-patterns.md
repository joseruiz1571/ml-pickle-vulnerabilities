# Remediation Patterns for Pickle Vulnerabilities

Secure alternatives to pickle-based model serialization in ML frameworks.

---

## The Core Problem

Python's pickle module can execute arbitrary code during deserialization. This is by design - pickle can serialize any Python object, including those with custom `__reduce__` methods that execute code when unpickled.

**There is no safe way to load an untrusted pickle file.** The only real solutions are:
1. Use formats that don't support code execution
2. Never load untrusted files
3. Sandbox the loading process

---

## Safe Serialization Formats

### 1. Safetensors (Recommended for Neural Networks)

Developed by Hugging Face specifically to address pickle security issues.

**Pros:**
- Cannot execute code during loading
- Fast loading (memory-mapped)
- Cross-platform (Rust, Python, JavaScript)
- Audited for security

**Cons:**
- Only stores tensors, not arbitrary Python objects
- Requires code changes to save/load

**Usage:**
```python
from safetensors.torch import save_file, load_file

# Save model weights
save_file(model.state_dict(), "model.safetensors")

# Load model weights
state_dict = load_file("model.safetensors")
model.load_state_dict(state_dict)
```

**Installation:**
```bash
pip install safetensors
```

### 2. ONNX (Open Neural Network Exchange)

Cross-platform format for neural network models.

**Pros:**
- Cannot execute arbitrary code
- Cross-framework (PyTorch → TensorFlow, etc.)
- Optimized inference runtimes

**Cons:**
- Not all operations supported
- Conversion can be complex

**Usage:**
```python
import torch
import onnx

# Export to ONNX
torch.onnx.export(model, dummy_input, "model.onnx")

# Load with ONNX Runtime (inference only)
import onnxruntime
session = onnxruntime.InferenceSession("model.onnx")
```

### 3. TorchScript

PyTorch's serialization format that captures model structure.

**Pros:**
- Native PyTorch support
- Can be loaded without Python (C++, mobile)
- Safer than pickle (but not immune)

**Cons:**
- Some Python operations not supported
- Still uses some pickle internally

**Usage:**
```python
import torch

# Save as TorchScript
scripted = torch.jit.script(model)
scripted.save("model_scripted.pt")

# Load
model = torch.jit.load("model_scripted.pt")
```

### 4. JSON/Protocol Buffers (for Non-Tensor Data)

For configuration, hyperparameters, metadata.

**Usage:**
```python
import json

# Instead of pickle for config
with open("config.json", "w") as f:
    json.dump(config_dict, f)

# Load
with open("config.json", "r") as f:
    config = json.load(f)
```

---

## Framework-Specific Migrations

### PyTorch

| From | To | Difficulty |
|------|-----|------------|
| `torch.save(model, "model.pt")` | safetensors | Low |
| `torch.save(model.state_dict(), "model.pt")` | safetensors | Low |
| `torch.load("model.pt")` | safetensors + model reconstruction | Medium |

**Migration Script:**
```python
import torch
from safetensors.torch import save_file

# Load existing pickle model
old_model = torch.load("legacy_model.pt", map_location="cpu")

# Save as safetensors
if hasattr(old_model, 'state_dict'):
    save_file(old_model.state_dict(), "model.safetensors")
else:
    save_file(old_model, "model.safetensors")
```

### Hugging Face Transformers

Many Hugging Face models now default to safetensors.

```python
from transformers import AutoModel

# Load preferring safetensors (default in recent versions)
model = AutoModel.from_pretrained("model_name")

# Save as safetensors
model.save_pretrained("output_dir", safe_serialization=True)
```

### scikit-learn

scikit-learn uses joblib (which uses pickle). Consider:

```python
# Option 1: ONNX conversion
from skl2onnx import convert_sklearn
onnx_model = convert_sklearn(sklearn_model, initial_types=initial_types)

# Option 2: Accept joblib but validate source
# Only load from trusted, version-controlled sources
```

---

## Defense in Depth

Even with safe formats, implement multiple layers:

### 1. Source Validation

```python
ALLOWED_SOURCES = [
    "huggingface.co/our-org/",
    "s3://our-bucket/models/"
]

def validate_source(url):
    return any(url.startswith(src) for src in ALLOWED_SOURCES)
```

### 2. Hash Verification

```python
import hashlib

def verify_model_hash(filepath, expected_hash):
    with open(filepath, 'rb') as f:
        actual_hash = hashlib.sha256(f.read()).hexdigest()
    return actual_hash == expected_hash
```

### 3. Sandboxed Loading

```python
# Run model loading in isolated container
# Example: Docker with no network, limited filesystem
docker run --rm --network none -v /models:/models:ro \
    model-loader python load_model.py
```

### 4. Monitoring

- Alert on unexpected model file downloads
- Log all model loading operations
- Monitor for suspicious process spawning after model loads

---

## Migration Checklist

- [ ] Inventory all model files in pickle format (.pkl, .pt, .pth, .joblib)
- [ ] Identify which models can be converted to safetensors
- [ ] Update model saving code to use safe formats
- [ ] Update model loading code
- [ ] Implement source validation for external models
- [ ] Add hash verification for critical models
- [ ] Test loading with new formats
- [ ] Update CI/CD pipelines
- [ ] Document new model handling procedures
- [ ] Train ML engineers on secure serialization

---

## Tools

### Pickle Scanning

```bash
pip install picklescan

# Scan a model file
picklescan model.pt

# Scan a directory
picklescan --path ./models/
```

**Note:** Picklescan can be bypassed (see CVE-2025-1716). Use as one layer, not sole defense.

### Conversion Tools

| From | To | Tool |
|------|-----|------|
| PyTorch | ONNX | torch.onnx.export |
| TensorFlow | ONNX | tf2onnx |
| scikit-learn | ONNX | skl2onnx |
| Any | Safetensors | safetensors library |

---

*Last updated: 2026-01-18*
