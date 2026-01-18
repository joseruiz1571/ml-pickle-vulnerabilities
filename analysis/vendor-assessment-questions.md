# Vendor Assessment Questions: ML Model Security

Use these questions when evaluating AI/ML vendors, conducting third-party risk assessments, or reviewing internal ML systems for pickle deserialization risks.

---

## Quick Assessment (5 Questions)

If you only have time for a brief evaluation:

1. **"How do you serialize and store ML models?"**
   - Red flags: "pickle", "joblib without validation", ".pkl files"
   - Good answers: "safetensors", "ONNX", "TensorFlow SavedModel with signature verification"

2. **"Do you load models from external sources (Hugging Face Hub, user uploads, third parties)?"**
   - If yes: "How do you validate model integrity before loading?"

3. **"What versions of PyTorch/TensorFlow/MLflow are in production?"**
   - Check against known vulnerable versions

4. **"How do you handle model files from customers or partners?"**
   - Red flags: "We load them directly", "We trust our partners"
   - Good answers: "Sandboxed processing", "Format conversion to safe formats"

5. **"Are your ML engineers aware of pickle deserialization risks?"**
   - Ask for evidence: training records, secure coding guidelines

---

## Detailed Assessment by Category

### Model Serialization & Storage

| Question | Why It Matters | Good Answer | Red Flag |
|----------|----------------|-------------|----------|
| What format do you use to serialize trained models? | Pickle formats enable code execution | safetensors, ONNX, protocol buffers | .pkl, .pt with pickle, joblib |
| How are model files stored and accessed? | Controls around model artifacts | Versioned, access-controlled, signed | Open file shares, no versioning |
| Do you sign or verify model files before loading? | Integrity verification | HMAC signatures, checksums, provenance tracking | No verification |
| Have you migrated from pickle to safer formats? | Awareness of the issue | Yes, with timeline | "What's wrong with pickle?" |

### Model Loading & Inference

| Question | Why It Matters | Good Answer | Red Flag |
|----------|----------------|-------------|----------|
| What function do you use to load PyTorch models? | torch.load vs torch.jit.load | torch.jit.load, safetensors.load_file | torch.load without weights_only |
| Do you use `weights_only=True` with torch.load? | Partial mitigation (still vulnerable in older versions) | Yes, AND PyTorch >= 2.6.0 | No, or old PyTorch version |
| Do you load TensorFlow/Keras models with custom objects? | Lambda layers can execute code | safe_mode=True (TF 2.13+), no custom objects | custom_objects from untrusted sources |
| How do you handle model loading in CI/CD pipelines? | Pipeline compromise risk | Sandboxed, minimal privileges | Runs as root, direct model loading |

### External Model Sources

| Question | Why It Matters | Good Answer | Red Flag |
|----------|----------------|-------------|----------|
| Do you download models from Hugging Face Hub? | Supply chain risk | Allowlisted models only, hash verification | Any model on request |
| Do you use `trust_remote_code=True`? | Enables arbitrary code execution | Never in production, reviewed case-by-case | Default or always enabled |
| How do you vet pre-trained models before use? | Model provenance | Security review, sandbox testing, known sources only | Download and use directly |
| Do you accept model uploads from users or customers? | User-supplied malicious models | Converted to safe format, sandboxed | Loaded directly |

### MLOps & Model Management

| Question | Why It Matters | Good Answer | Red Flag |
|----------|----------------|-------------|----------|
| What MLflow version do you run? | CVE-2024-37052 through CVE-2024-37060 | >= 2.14.2 | < 2.14.2 |
| Who can register models in your Model Registry? | Unauthorized model injection | Role-based access, approval workflow | Anyone can register |
| How do you track model provenance? | Detecting tampered models | ML Bill of Materials, lineage tracking | No tracking |
| Do you scan model files for malicious content? | Detection layer | Picklescan (0.0.23+) in sandboxed env | No scanning, or outdated scanner |

### LLM-Specific Questions

| Question | Why It Matters | Good Answer | Red Flag |
|----------|----------------|-------------|----------|
| What framework do you use to serve LLMs? | Llama Stack CVE-2024-50050 | vLLM, TGI, or patched Llama Stack (>= 0.0.41) | Unpatched Llama Stack |
| How do you serialize messages between LLM services? | Pickle-over-network risk | JSON, protobuf, gRPC | Pickle |
| Do you use RAG (Retrieval-Augmented Generation)? | CVE-2023-6730 index loading | Local indices only, validated sources | Remote index loading |

---

## Framework-Specific Version Checks

### Minimum Safe Versions

| Framework | Minimum Safe Version | Key CVE Fixed |
|-----------|---------------------|---------------|
| PyTorch | 2.6.0 | CVE-2025-32434 |
| Transformers | 4.36.0 | CVE-2023-6730, CVE-2023-7018 |
| MLflow | 2.14.2 | CVE-2024-37052 through CVE-2024-37060 |
| Llama Stack | 0.0.41 | CVE-2024-50050 |
| Picklescan | 0.0.23 | CVE-2025-1716 and related |
| TensorFlow | 2.13.0 | safe_mode support for Keras |

### Version Check Script

Provide this to vendors to verify their versions:

```bash
pip show torch transformers mlflow | grep -E "^(Name|Version)"
```

---

## Evidence Requests

When vendors claim they've addressed these risks, ask for:

1. **Dependency manifest** showing framework versions
2. **Code snippets** showing model loading patterns
3. **Architecture diagram** showing model flow and trust boundaries
4. **Security training records** for ML engineers
5. **Vulnerability scan results** for ML dependencies
6. **Incident response plan** for model supply chain attacks

---

## Risk Rating Guide

Based on answers, rate the vendor's ML model security posture:

### Low Risk
- Uses safetensors or ONNX exclusively
- All frameworks at safe versions
- No external model sources, or strict validation
- Security-aware ML team
- Model signing and provenance tracking

### Medium Risk
- Uses pickle but with mitigations (sandboxing, scanning)
- Frameworks mostly current, upgrade plan in place
- External models from vetted sources only
- Some security awareness

### High Risk
- Uses pickle without mitigations
- Outdated framework versions
- Loads models from arbitrary external sources
- No awareness of deserialization risks
- User-uploaded models loaded directly

### Critical Risk
- Network-exposed model loading endpoints
- No input validation on model files
- trust_remote_code=True in production
- Pickle used for inter-service communication

---

## Sample Assessment Report Language

### Finding Template

> **Finding: Insecure Model Deserialization**
>
> **Risk Level:** [High/Medium/Low]
>
> **Description:** The vendor uses PyTorch's `torch.load()` function to load model files from [source]. This function uses Python's pickle module, which can execute arbitrary code during deserialization (CWE-502).
>
> **Evidence:** [Version info, code pattern, architecture description]
>
> **Affected CVEs:** CVE-2025-32434, CVE-2024-37059
>
> **Recommendation:** Upgrade to PyTorch >= 2.6.0 and migrate to safetensors format for model serialization.

---

*Last updated: 2026-01-18*
