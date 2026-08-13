# Render Deployment Guide: Transformer-WAF Gateway

This guide provides step-by-step instructions for deploying the **Transformer-WAF** as a real, functional Web Application Firewall (WAF) reverse proxy on [Render](https://render.com).

## Architecture

```text
       Internet
          |
          v
   +--------------+ 
   | Render WAF   |
   | (FastAPI)    |
   +--------------+
          | (Proxy)
          v
+--------------------+
| Protected App      |
| (Target Service)   |
+--------------------+
```

The WAF acts as the public entry point. It inspects incoming HTTP requests, runs them through the Transformer ML model, and based on the configuration (`detection_mode`), either forwards them to the protected application or blocks them with an HTTP 403 response.

## STEP 1: Push Repository to GitHub
Ensure all your local changes (including the WAF gateway implementation in `api/waf_api.py`) are pushed to a GitHub repository connected to your Render account.

## STEP 2: Deploy the Protected Application
Before deploying the WAF, you need a target application to protect.
1. Deploy your target web service (e.g., a vulnerable test app or a production backend) on Render.
2. Note the public URL (e.g., `https://my-protected-app.onrender.com`).
3. (Optional but recommended) Configure your protected app to only accept requests coming from the WAF's IP or passing a specific secret header, ensuring attackers cannot bypass the WAF.

## STEP 3: Create Render Backend Service (WAF API)
1. In the Render Dashboard, click **New +** and select **Web Service**.
2. Connect your GitHub repository.
3. Configure the service:
   - **Name**: `transformer-waf-api`
   - **Environment**: `Python 3`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn -k uvicorn.workers.UvicornWorker api.waf_api:app --bind 0.0.0.0:$PORT`
   
### Step 3.1: Configure Environment Variables
Set the following environment variables in the Render dashboard for the API service:
- `PYTHON_VERSION`: `3.10.0` (or your preferred version)
- `WAF_UPSTREAM_URL`: `https://my-protected-app.onrender.com` *(The URL from Step 2)*
- `WAF_ANOMALY_THRESHOLD`: `0.75`
- `WAF_DETECTION_MODE`: `block` (or `detect` / `monitor`)
- `WAF_DEVICE`: `cpu` (Unless you are deploying on a Render GPU instance, then use `cuda`)

## STEP 4: Deploy the Backend
Click **Create Web Service**. Wait for the build to complete and the service to start.

## STEP 5: Verify Backend Health
Once deployed, verify the API is running by visiting:
`https://transformer-waf-api.onrender.com/health`
You should see a JSON response indicating the model is loaded and the status is healthy.

## STEP 6: Create Frontend Service (Dashboard)
1. In the Render Dashboard, click **New +** and select **Static Site**.
2. Connect the same GitHub repository.
3. Configure the service:
   - **Name**: `transformer-waf-dashboard`
   - **Root Directory**: `frontend`
   - **Build Command**: `npm install && npm run build`
   - **Publish Directory**: `dist` (or `build`, depending on your Vite config)

### Step 6.1: Configure Frontend Environment Variables
Set the following environment variables:
- `VITE_API_URL`: `https://transformer-waf-api.onrender.com`
- `VITE_WS_URL`: `wss://transformer-waf-api.onrender.com`

*Note: It is crucial to use `wss://` instead of `ws://` in production.*

## STEP 7: Configure SPA Routing (Important)
Since the frontend is a Single Page Application (React Router), you must configure Render to rewrite all paths to `index.html`.
1. Go to your Static Site settings on Render.
2. Navigate to **Redirects/Rewrites**.
3. Add a rule:
   - **Source**: `/*`
   - **Destination**: `/index.html`
   - **Action**: `Rewrite`

## STEP 8: Deploy Frontend
Click **Create Static Site** and wait for the deployment to finish.

## STEP 9: End-to-End Testing

### Test 1: Normal Request
In your terminal, make a standard request to the WAF:
```bash
curl -i https://transformer-waf-api.onrender.com/api/users
```
**Expected Outcome**: The request is forwarded to your protected app, and you receive a `200 OK` (or whatever the app responds with). The Dashboard will show the request as ALLOWED.

### Test 2: Controlled Malicious Payload (Block Mode)
Ensure the WAF is in `block` mode (via the Settings dashboard or environment variable).
```bash
curl -i "https://transformer-waf-api.onrender.com/api/users?id=1'%20OR%20'1'='1"
```
**Expected Outcome**: You receive a `403 Forbidden` from the WAF. The request never reaches the protected app. The Live Monitoring dashboard instantly highlights the blocked SQL Injection attempt.

### Test 3: Monitor Mode
Change the detection mode to `monitor` in the WAF settings.
Repeat the malicious payload test.
**Expected Outcome**: The request is forwarded to the upstream app, but the WAF logs the anomaly, and the dashboard marks it as a detected threat (without blocking).

## Limitations & Security Considerations
- **Memory Consumption**: PyTorch and Transformer models can consume significant memory. Ensure your Render instance has at least 2GB-4GB of RAM.
- **Latency**: CPU inference adds overhead (~50-150ms per request). Use a GPU-backed instance for optimal performance in high-traffic environments.
- **Bypass Risk**: If your protected application's direct Render URL is known, attackers can bypass the WAF. Secure the upstream app using IP restrictions, mTLS, or shared secret headers.
