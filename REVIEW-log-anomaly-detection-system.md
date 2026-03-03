# Code Review: canthaxit/Log-Anomaly-Detection-System

**Repository:** https://github.com/canthaxit/Log-Anomaly-Detection-System
**Review Date:** 2026-03-03
**Reviewer:** Claude (Automated Code Review)

---

## 1. Executive Summary

This is an AI-powered log anomaly detection system that uses unsupervised machine learning (Isolation Forest + statistical rules) to identify security threats in system logs. The project provides a CLI pipeline, REST API (FastAPI), Google Chronicle SIEM integration, MCP server for Claude Desktop, batch processing, and Docker deployment.

**Overall Assessment:** The project demonstrates a well-structured, modular approach to log-based threat detection with broad integration options. However, there are significant **security vulnerabilities**, **code quality issues**, and **architectural concerns** that should be addressed before production use.

**Risk Rating: MEDIUM-HIGH** — The system has exploitable security issues (path traversal, pickle deserialization, open CORS) and lacks testing, input validation, and authentication on its API surface.

---

## 2. Architecture Overview

```
core/
  log_anomaly_detection_lite.py   — Main detection pipeline (Isolation Forest + Statistical)
  intrusion_detection_pipeline.py — Full version with Autoencoder/TensorFlow

api/
  anomaly_api.py                  — FastAPI REST API server
  anomaly_api_chronicle.py        — API with Chronicle SIEM forwarding
  test_api.py                     — Basic integration test script

chronicle/
  google_chronicle_integration.py — Chronicle client, UDM conversion, YARA-L rules

mcp/
  anomaly_mcp_server.py           — MCP server for Claude Desktop

batch/
  batch_processor.py              — Scheduled batch log processing

docker/
  Dockerfile, docker-compose.yml  — Container deployment

config/
  requirements*.txt               — Dependency manifests
```

---

## 3. Security Findings

### 3.1 CRITICAL: Unsafe Deserialization via `joblib.load` / Pickle

**Files:** `anomaly_api.py`, `anomaly_api_chronicle.py`, `batch_processor.py`, `anomaly_mcp_server.py`

All model-loading paths use `joblib.load()` on user-configurable paths without any integrity verification:

```python
MODEL_STATE["feature_pipeline"] = joblib.load(model_path / "feature_pipeline.pkl")
MODEL_STATE["isolation_forest"] = joblib.load(model_path / "isolation_forest_model.pkl")
```

The `/models/load` API endpoint accepts a `model_dir` parameter from the client:

```python
@app.post("/models/load")
async def load_models(model_dir: str = "anomaly_outputs"):
```

**Impact:** An attacker who can write to the filesystem or control the `model_dir` parameter can achieve **arbitrary code execution** by crafting a malicious pickle file. This is a well-known attack vector (CWE-502).

**Recommendation:**
- Restrict `model_dir` to a hardcoded allowlist or single path, never accepting user input.
- Add HMAC/signature verification on serialized model files before loading.
- Consider using safer serialization formats (ONNX, safetensors) for production.

### 3.2 HIGH: Path Traversal in Model Loading and File Upload

**File:** `anomaly_api.py` — `/models/load` endpoint

```python
model_path = Path(model_dir)
```

No sanitization is performed on `model_dir`. An attacker can supply `../../etc/` or absolute paths to read arbitrary `.pkl` files from the filesystem.

**File:** `anomaly_api.py` — `/analyze/file` endpoint

The file upload endpoint parses filenames to determine format but does not sanitize or restrict filenames:

```python
if file.filename.endswith('.json'):
```

**Recommendation:**
- Validate that the resolved path is within the expected directory using `Path.resolve()` and prefix checks.
- Never expose `model_dir` as an API parameter in production.

### 3.3 HIGH: No Authentication or Authorization

**Files:** `anomaly_api.py`, `anomaly_api_chronicle.py`

The API has **zero authentication**. All endpoints are publicly accessible:

```python
app = FastAPI(title="Log Anomaly Detection API", ...)
```

No API keys, JWT tokens, OAuth, or any auth mechanism exists. This exposes:
- Model loading/replacement (could load malicious models)
- Log analysis (information leakage via results)
- Chronicle enable/disable (could disrupt SIEM integration)
- System statistics (reconnaissance)

**Recommendation:**
- Add API key or bearer token authentication at minimum.
- Use FastAPI's dependency injection for auth middleware.
- Restrict `/models/load` and `/chronicle/*` to admin roles.

### 3.4 HIGH: Overly Permissive CORS

**Files:** `anomaly_api.py`, `anomaly_api_chronicle.py`

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

`allow_origins=["*"]` with `allow_credentials=True` is an insecure configuration. Browsers will send cookies/credentials to this API from any origin.

**Recommendation:**
- Restrict `allow_origins` to specific trusted domains.
- Never combine `allow_origins=["*"]` with `allow_credentials=True`.

### 3.5 MEDIUM: Bare Exception Handlers Mask Errors and Leak Details

Throughout the codebase, broad `except Exception as e` blocks are used, and error messages are returned directly to clients:

```python
except Exception as e:
    logger.error(f"Analysis failed: {e}")
    raise HTTPException(status_code=500, detail=str(e))
```

**Impact:** Internal stack traces, file paths, and system details can leak to attackers via error messages.

**Recommendation:**
- Return generic error messages to clients.
- Log full details server-side.
- Use specific exception types.

### 3.6 MEDIUM: Docker Container Runs as Root

The Dockerfile does not specify a non-root user. The container process runs as root by default, increasing blast radius if the container is compromised.

**Recommendation:**
- Add `RUN useradd -m appuser` and `USER appuser` to the Dockerfile.

---

## 4. Code Quality Findings

### 4.1 Massive Code Duplication

The `classify_threat()` and `assign_severity()` functions are **copy-pasted identically** across four files:
- `anomaly_api.py`
- `anomaly_api_chronicle.py`
- `batch_processor.py`
- `anomaly_mcp_server.py` (inferred)

The threat classification logic in the API (`classify_threat`) is also a **degraded version** of the core module's `classify_threat_type()` — the API version uses simplistic string matching while the core module runs the full statistical detectors. This means the API returns less accurate threat classifications than the CLI pipeline.

**Recommendation:**
- Extract shared functions into a common utility module (e.g., `core/utils.py`).
- Have all consumers import from the single source of truth.

### 4.2 The Lite vs Full Pipeline Divergence

Two separate pipeline files exist (`log_anomaly_detection_lite.py` and `intrusion_detection_pipeline.py`) with substantial code duplication. The full version adds an autoencoder but duplicates all other logic (parsing, feature engineering, statistical detection, reporting).

**Recommendation:**
- Use a single pipeline with optional components. The autoencoder should be a pluggable detector, not a reason to fork the entire codebase.

### 4.3 Global Mutable State in API

```python
MODEL_STATE = {
    "feature_pipeline": None,
    "isolation_forest": None,
    ...
}
```

The API uses module-level mutable dictionaries for state. This is **not thread-safe** and will cause race conditions under concurrent requests (e.g., if `/models/load` is called while `/analyze` is in progress).

**Recommendation:**
- Encapsulate state in a class with proper locking.
- Use FastAPI's dependency injection pattern with `Depends()`.
- Consider a singleton pattern with a read-write lock for model hot-reloading.

### 4.4 Rolling Window Features Are Not Actually Rolling

In `LogFeaturePipeline._extract_features()`:

```python
for window in self.time_windows:
    window_name = f"{window}s"
    # Use simple count instead of time-based rolling for compatibility
    X_sorted[f'events_per_{window_name}'] = X_sorted.groupby('user').cumcount() + 1
```

The comment says "time-based rolling" but the implementation is a **cumulative count** — it counts all prior events, not events within the specified time window. This means the 1-hour, 1-day, and 1-week window features are all identical (just monotonically incrementing counters). This significantly reduces the model's ability to detect burst patterns like brute force attacks.

**Recommendation:**
- Implement actual time-windowed aggregations using `pd.Grouper` with time-based windows or manual timestamp-based filtering.

### 4.5 Feature Name Mismatch at Transform Time

The feature pipeline creates event-type features based on the top 10 events in the training data:

```python
top_events = X['event_type'].value_counts().head(10).index.tolist()
for event in top_events:
    features[f'event_{event}'] = (X['event_type'] == event).astype(int)
```

At transform time, the code handles missing/extra columns, but the top events are re-computed from the new data rather than stored from fit time. This means if the analysis data has different event distributions, the feature set will differ and the column reconciliation logic silently drops or zeros-out features.

**Recommendation:**
- Store `top_events` during `fit()` and reuse them during `transform()`.

### 4.6 `np.random.seed()` Called Globally

```python
def _set_seeds(self):
    np.random.seed(self.random_state)
```

Using `np.random.seed()` sets the global random state, which affects all numpy operations across the process. This is especially problematic in the API server where concurrent requests share the same process.

**Recommendation:**
- Use `np.random.RandomState` or `np.random.default_rng()` instances instead of global seed.

### 4.7 Bare `except:` Clauses

Several places use bare `except:` (no exception type) or overly broad `except Exception`:

```python
try:
    config = ChronicleConfig()
    if Path(config.get("credentials_file")).exists():
        await enable_chronicle()
except:
    logger.info("Chronicle auto-enable skipped (not configured)")
```

This silently swallows all errors including `KeyboardInterrupt`, `SystemExit`, and genuine bugs.

**Recommendation:**
- Always catch specific exception types.
- At minimum, use `except Exception` rather than bare `except`.

---

## 5. ML/Detection Logic Findings

### 5.1 Equal Weighting of Isolation Forest and Statistical Detectors

```python
self.weights = {
    'isolation_forest': 0.50,
    'statistical': 0.50
}
```

The 50/50 weighting is arbitrary. In practice, these detectors have very different characteristics:
- **Isolation Forest** is good at finding multivariate outliers but needs well-engineered features.
- **Statistical rules** are precise for known patterns but miss novel attacks.

**Recommendation:**
- Make weights configurable via the config system.
- Consider calibration on a validation set.
- Document the rationale for the chosen weights.

### 5.2 Threshold Calibration Uses Percentile, Not FPR

```python
def calibrate_threshold(self, scores, false_positive_rate=0.01):
    return np.percentile(scores, (1 - false_positive_rate) * 100)
```

This assumes anomaly scores follow a uniform distribution, which they don't. The parameter is named `false_positive_rate` but is actually just a percentile cutoff. The actual FPR depends on the score distribution and will typically differ from the specified value.

**Recommendation:**
- Rename the parameter to `percentile_cutoff` for clarity, or implement actual FPR-based calibration using labeled validation data when available.

### 5.3 Brute Force Detection Uses Cumulative Count, Not Windowed

```python
df_sorted['failed_count'] = df_sorted[failed_mask].groupby('user').cumcount() + 1
scores = (df_sorted.set_index(df.index)['failed_count'] / self.brute_force_threshold).fillna(0).values
```

The brute force detector counts **all historical failures** for a user, not failures within a time window. A user with 10 failed logins spread over a month gets the same score as 10 failures in 10 seconds. This generates false positives for legitimate users with accumulated lockouts and misses the temporal burst signature of actual brute force attacks.

**Recommendation:**
- Implement time-windowed failure counting (e.g., failures in last 5 minutes).

### 5.4 Baseline vs. Analysis Split Is Fragile

```python
cutoff_date = df['timestamp'].min() + pd.Timedelta(days=config.baseline_period_days)
baseline_df = df[df['timestamp'] < cutoff_date].copy()
analysis_df = df[df['timestamp'] >= cutoff_date].copy()
```

The split assumes the first N days of data are "normal." If the dataset begins with an attack, the entire baseline is poisoned, and the model learns attack patterns as normal behavior.

**Recommendation:**
- Add data quality checks on the baseline period (alert if baseline has high failure rates, unusual patterns).
- Consider allowing users to specify explicit baseline time ranges.
- Document this assumption prominently.

---

## 6. Testing Findings

### 6.1 No Unit Tests

The project has **zero unit tests**. The only test file (`test_api.py`) is an integration test script that requires the API to be running. There are no tests for:

- Log parsing correctness
- Feature extraction accuracy
- Anomaly scoring logic
- Threat classification
- Edge cases (empty logs, malformed timestamps, missing fields)

**Recommendation:**
- Add a proper test suite using `pytest`.
- Test each component in isolation: parser, feature pipeline, detectors, scorer.
- Add edge case tests (empty input, single event, all anomalies, no anomalies).

### 6.2 Test Data Is Minimal

The test directory contains only two small JSON files (10 normal + 18 attack events). This is insufficient for validating ML model behavior.

**Recommendation:**
- Add larger synthetic datasets.
- Add test cases for each threat type.
- Add regression test data from known detection scenarios.

---

## 7. Dependency & Packaging Findings

### 7.1 No `pyproject.toml`, `setup.py`, or Package Structure

The project is a loose collection of Python scripts with no installable package structure. Modules import each other using relative file-based imports (e.g., `from log_anomaly_detection_lite import ...`), which breaks unless scripts are run from specific directories.

**Recommendation:**
- Add a proper Python package structure with `__init__.py` and a `pyproject.toml`.
- Use proper package imports instead of file-based imports.

### 7.2 Multiple Requirements Files Without Clear Separation

There are 4 requirements files (`requirements.txt`, `requirements_api.txt`, `requirements_chronicle.txt`, `requirements_minimal.txt`) but no clear tooling to manage them. The main `requirements.txt` includes TensorFlow, but the lite version doesn't need it.

**Recommendation:**
- Consolidate into optional dependency groups in `pyproject.toml` (e.g., `pip install .[api]`, `pip install .[chronicle]`).

### 7.3 Version Pinning Is Insufficient

Dependencies use `>=` minimum versions only (e.g., `pandas>=2.0.0`). No upper bounds or hash pinning.

**Recommendation:**
- Generate a `requirements.lock` or use `pip-compile` for reproducible builds.
- Pin exact versions in Docker images for production.

---

## 8. Documentation Findings

### 8.1 Strengths
- Clear README with quick start instructions
- Architecture diagram in the README
- Individual README files per module
- Example integration code

### 8.2 Weaknesses
- No API documentation beyond FastAPI's auto-generated `/docs`
- No explanation of the ML methodology, feature engineering rationale, or detection tuning guidance
- The `MIGRATION_GUIDE.md` suggests the project underwent a major restructuring — but no changelog explaining what changed
- No threat model or security considerations document

---

## 9. Positive Observations

1. **Clean modular structure** — Each concern (core, API, batch, integrations) has its own directory.
2. **Multiple deployment modes** — CLI, API, batch, MCP, Docker — gives users flexibility.
3. **Google Chronicle UDM mapping** is well done and follows the Chronicle schema.
4. **YARA-L rule generation** for Chronicle is a nice touch for automated detection engineering.
5. **The lite version** is a pragmatic decision for environments where TensorFlow isn't available.
6. **Configurable contamination rate** and CLI args make the tool adaptable.
7. **Visualization output** with matplotlib provides useful analysis artifacts.
8. **Artifact persistence** via joblib allows model reuse across runs.

---

## 10. Summary of Recommendations

### Must Fix (Security)
| # | Finding | Severity | Effort |
|---|---------|----------|--------|
| 1 | Unsafe pickle deserialization on user-controlled paths | CRITICAL | Medium |
| 2 | Path traversal in `/models/load` endpoint | HIGH | Low |
| 3 | No API authentication | HIGH | Medium |
| 4 | Overly permissive CORS (`*` + credentials) | HIGH | Low |
| 5 | Docker container runs as root | MEDIUM | Low |
| 6 | Error messages leak internal details | MEDIUM | Low |

### Should Fix (Quality)
| # | Finding | Impact | Effort |
|---|---------|--------|--------|
| 7 | Duplicate code across 4+ files | Maintainability | Medium |
| 8 | Rolling window features are cumulative, not windowed | Detection accuracy | Medium |
| 9 | Global mutable state in API (not thread-safe) | Reliability | Medium |
| 10 | Feature name mismatch between fit/transform | Detection accuracy | Low |
| 11 | No unit tests | Reliability | High |
| 12 | Brute force detection lacks time windowing | Detection accuracy | Medium |

### Nice to Have
| # | Finding | Impact | Effort |
|---|---------|--------|--------|
| 13 | Add proper Python packaging | Usability | Medium |
| 14 | Consolidate requirements into pyproject.toml | Maintainability | Low |
| 15 | Make ensemble weights configurable | Flexibility | Low |
| 16 | Add ML methodology documentation | Usability | Medium |
| 17 | Poisoned baseline detection | Detection accuracy | Medium |

---

*End of Review*
