# WAF Demo Site

A minimal FastAPI demo site to generate normal and attack-style requests.

## Run

1. Start the WAF API on port 8000.
2. Start this demo site on port 5000:

```bash
py demo_site/app.py
```

3. Start the WAF reverse proxy on port 8080:

```bash
py integration/waf_reverse_proxy.py
```

4. Open the site through the proxy:

```
http://localhost:8080
```

The WAF dashboard should now show live traffic.

## Notes

- Do not open http://localhost:5000 directly if you want WAF events.
- To block anomalies, set WAF detection mode to `block` in Settings.
