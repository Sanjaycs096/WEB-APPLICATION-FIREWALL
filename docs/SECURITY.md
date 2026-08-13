# Transformer-WAF Gateway: Security Architecture & Threat Model

## 1. Threat Model & Trust Boundaries

The **Transformer-WAF Gateway** operates as an inline Layer 7 reverse proxy. 

### Trust Boundaries
1. **Untrusted Zone**: The public internet. Clients interacting with the WAF are assumed malicious.
2. **Semi-Trusted Zone**: The WAF Gateway itself. It parses untrusted input and attempts to classify it via Machine Learning inference.
3. **Trusted Zone**: The protected upstream web application. It relies implicitly on the WAF dropping malicious packets.
4. **Configuration Zone**: The WAF Dashboard. Changes must be authenticated via strict API keys.

## 2. Authentication & Authorization

- **Configuration Endpoints** (`/config`, `/threshold`): Enforced via the `x-api-key` header mapped against the backend environment variable `WAF_API_KEY`. Without a valid key, the API yields `401 Unauthorized`.
- **Dashboard Authorization**: The React frontend is explicitly treated as untrusted. Security policies and anomaly thresholds are strictly evaluated in the backend Python runtime, preventing client-side manipulation of firewall states.

## 3. Upstream Bypass Protection

**CRITICAL RISK**: If the origin server (the protected upstream application) exposes a public IP address or endpoint directly to the internet, attackers can bypass the WAF Gateway entirely.

**Mitigation Strategies**:
- **IP Whitelisting**: Configure the target application to explicitly drop connections originating from any IP other than the WAF Gateway's deployment IP (e.g., Render outbound IPs).
- **VPC / Private Network**: Deploy the WAF and Target application within the same Virtual Private Cloud.
- **Mutual TLS (mTLS) / Shared Secrets**: Require the target application to validate a cryptographically secure header appended exclusively by the WAF.

## 4. SSRF (Server-Side Request Forgery) Mitigation

The proxy forwarding destination (`WAF_UPSTREAM_URL`) is heavily restricted:
- It **cannot** be altered dynamically via standard API payload injection.
- It is instantiated exclusively through environment variables at startup.
- The proxy appends client paths strictly to the base URL, preventing arbitrary hostname traversal.

## 5. Header Sanitization

To mitigate HTTP Desync, Smuggling, and Spoofing:
- **Hop-by-hop headers** (e.g., `Connection`, `Keep-Alive`, `Upgrade`, `Proxy-Authorization`, `TE`) are forcefully stripped before routing to the upstream application.
- WAF-generated internal headers cannot be overridden by external request spoofing.

## 6. Denial of Service (DoS) & Resource Limitations

- **Request Size Limits**: Payload sizes are evaluated prior to inference. Payloads exceeding the configured threshold will immediately yield a `413 Payload Too Large` response to prevent memory exhaustion (OOM).
- **Concurrency**: ML Inference is bound using internal semaphores, ensuring that aggressive traffic spikes queue gracefully rather than locking the main FastAPI event loop (preventing Head-of-Line blocking).
- **Upstream Failures**: If the upstream application crashes or times out, the WAF catches the exception and returns a sanitized `502 Bad Gateway` or `504 Gateway Timeout` without leaking Python stack traces.

## 7. Forensic Log Redaction

The WAF utilizes structured JSON logging via `WAFLogger`. To maintain GDPR and compliance integrity:
- High-risk credential fields (e.g., `authorization`, `cookie`, `password`, `token`) are automatically sanitized using regex pattern matching and replaced with `***REDACTED***`.

## 8. Known Limitations
- **WebSockets**: The current proxy pipeline inspects and forwards standard REST/HTTP traffic. It does **not** proxy WebSocket connection upgrades (`Upgrade: websocket`) through to the upstream application natively. (Note: The WAF's internal live-monitoring dashboard WebSocket functions normally).
- **Memory Overhead**: CPU-based execution of DistilBERT models requires a minimum baseline of 2GB-4GB RAM to prevent OOM errors during concurrent load spikes.
