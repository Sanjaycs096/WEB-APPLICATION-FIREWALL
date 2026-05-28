# Technologies Used and ML Training Details

This document summarizes the technology stack and the machine learning training pipeline for the Transformer WAF. It is meant to be read before a presentation.

## 1) Technology Stack

### Backend (WAF API)
- Python 3.10+
- FastAPI for the REST API and WebSocket streaming
- Uvicorn for the ASGI server
- Pydantic for request validation and typed config
- aiohttp and requests for HTTP clients and integrations

### ML / Data
- PyTorch for model training and inference
- Hugging Face Transformers for pretrained encoders and tokenizers
- Tokenizers for fast subword tokenization
- NumPy and Pandas for data processing
- tqdm for training progress tracking

### Frontend (Dashboard)
- React 18 with TypeScript
- Vite for build and dev server
- Tailwind CSS for UI
- Recharts for charts
- Axios for API calls

### DevOps / Deployment
- Docker (optional) for containerization
- Nginx / Apache integration examples
- PowerShell and batch scripts for Windows startup

## 2) High-Level ML Approach

The WAF uses an anomaly detection strategy:
- Train only on benign traffic.
- Learn the normal structure of HTTP requests.
- Mark large deviations from that normal pattern as anomalous.

Model family: Transformer autoencoder with a pretrained encoder (DistilBERT by default).

## 3) Training Data Flow

1. Collect benign HTTP access logs (Apache or Nginx combined format).
2. Parse logs into structured request fields (method, path, query, headers).
3. Normalize requests to remove noisy dynamic tokens (IDs, UUIDs, timestamps, hashes, emails, IPs).
4. Tokenize normalized text with a Transformer-compatible tokenizer.
5. Train the model with Masked Language Modeling (MLM) on the benign data.

## 4) Normalization Rules

The normalizer reduces variance so the model can focus on structure rather than unique values. It replaces:
- IP addresses, UUIDs, hashes, timestamps
- Session IDs, JWTs, long numbers
- Emails, phone numbers, credit card patterns
- Numeric IDs in paths and query strings

Normalization produces compact text like:

```
GET /api/users/[ID] ?id=[ID] UA:mozilla/5.0
```

## 5) Tokenization

- Uses a pretrained tokenizer (DistilBERT by default).
- Maximum sequence length: 128 tokens.
- Padding and truncation are enabled for fixed-length batches.

## 6) Model Architecture

**Transformer Autoencoder**
- Encoder: pretrained Transformer (DistilBERT by default).
- Reconstruction head: predicts original tokens from the encoder output.
- Optional classifier head (supervised) can be enabled for hybrid scoring.

## 7) Training Algorithm

**Masked Language Modeling (MLM)** on benign requests:
- 15% of tokens are selected for masking.
- 80% replaced with [MASK]
- 10% replaced with random tokens
- 10% kept unchanged

Loss function:
- Cross-entropy over masked tokens (standard MLM).

Optimization:
- AdamW optimizer
- Linear warmup and learning-rate schedule
- Gradient clipping for stability

## 8) Anomaly Scoring (Inference)

At inference, each request is normalized and tokenized, then passed through the model. The system computes a combined anomaly score using multiple signals:
- Reconstruction error (token mismatch rate)
- Perplexity (language model uncertainty)
- Attention pattern anomaly
- Embedding distance (Mahalanobis distance in embedding space)

The system calibrates and thresholds the final score to decide:
- Monitor (log only)
- Detect (log + alert)
- Block (deny request)

## 9) Inference Pipeline

1. Receive request payload at `/scan`.
2. Normalize and tokenize.
3. Run model inference.
4. Compute anomaly score + confidence.
5. Compare against configurable threshold.
6. Emit WebSocket event and update metrics.

## 10) Continuous Learning (Optional)

The system can fine-tune on new verified benign traffic:
- Collect recent benign samples.
- Validate for drift.
- Fine-tune for a few epochs with a lower learning rate.
- Save a new model version.

This keeps the model aligned with evolving normal traffic patterns.

## 11) Practical Notes for the Demo

- Demo mode generates both benign and attack-like requests.
- For real traffic, use the reverse proxy to route requests through the WAF.
- Set `detection_mode` to `block` to enforce blocking behavior.

## 12) Where This Lives in the Repo

- Training pipeline: `model/train.py`
- Model architecture: `model/transformer_model.py`
- Normalizer: `parsing/normalizer.py`
- Tokenizer: `tokenization/tokenizer.py`
- Inference: `inference/detector.py`
- API service: `api/waf_api.py`
- Dashboard: `frontend/`
