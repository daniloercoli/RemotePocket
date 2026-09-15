# Monitoring alerts

The server exposes Prometheus metrics at `/metrics` when `MYDESK_METRICS_ENABLED=true` and a dedicated `MYDESK_MONITORING_TOKEN` is configured. Every scrape must authenticate with that token. Prometheus evaluates alert rules and Alertmanager sends notifications. These services are configured separately from the MyDesk Compose stack.

## Setup

1. Use [prometheus.yml](../monitoring/prometheus.yml) as the starting configuration. Replace `desk.example.com` with your MyDesk domain and use a valid HTTPS certificate.
2. Generate a random token of at least 32 characters, independent of your JWT and encryption keys. Set it as `MYDESK_MONITORING_TOKEN` in the app's deployment environment (or mount the corresponding Docker secret), then restart/recreate the app. Put the same token in a protected file mounted read-only at `/run/secrets/mydesk_monitoring_token`. The example configuration sends it in the Authorization header; never put it in the scrape URL or commit it to Git. Rotating it requires updating both sides. Ordinary account tokens are rejected.
3. Mount [alert-rules.yml](../monitoring/alert-rules.yml) at `/etc/prometheus/alert-rules.yml` in Prometheus.
4. Configure a notification recipient in [alertmanager.example.yml](../monitoring/alertmanager.example.yml). Make sure Prometheus can reach Alertmanager at the configured address.
5. Validate your installed configuration files:

```bash
promtool check config /etc/prometheus/prometheus.yml
promtool check rules /etc/prometheus/alert-rules.yml
amtool check-config /etc/alertmanager/alertmanager.yml
```

Send a test alert in your deployment environment and check that both the alert and its resolution reach the configured recipient. Keep notification credentials outside the repository.

## Included rules

The rules cover HTTP errors above 5%, response latency with p95 above 500 ms, failed scrapes, failed readiness checks, spikes in failed logins or WebSocket disconnections, and database pool usage above 90%.

All rules select `job="mydesk"`. HTTP status labels contain full status codes, so `status=~"5.."` matches server errors. Adjust thresholds to your measured traffic.

`mydesk_ready` reflects the last health or readiness probe. Keep the Docker health check enabled, or poll the health endpoint regularly when running outside Docker. Connection and session metrics describe the single backend process.

Including these files in the repository does not install Prometheus or Alertmanager, or enable notifications by itself.
