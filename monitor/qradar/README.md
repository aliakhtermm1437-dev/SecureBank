# IBM QRadar Integration

This folder documents the QRadar configuration used by SecureBank.

## 1. Log sources

| Source | Protocol | DSM |
|--------|----------|-----|
| `securebank-loki-bridge` | HTTPS POST (JSON) | Universal CEF DSM with custom mappings |
| `falco-events` | Syslog UDP 514 | Universal LEEF DSM (see `dsm/falco-leef.xml`) |
| `kubernetes-audit` | Kubernetes Audit Log API | Built-in K8s DSM |
| `nginx-ingress` | HTTPS POST | NGINX DSM |

## 2. Forwarding from Loki → QRadar

A small forwarder (`loki-to-qradar.py`) tails security-relevant streams and
posts CEF events to QRadar's HTTP receiver:

```bash
python loki-to-qradar.py \
  --loki-url http://loki:3100 \
  --qradar-url https://qradar.securebank.local/api/log_source/event \
  --query '{job=~"securebank.*"} |= "audit"'
```

## 3. Correlation Rules

See `rules/`:

- `cred-stuffing.aql` — > 30 failed logins from same IP in 5 minutes
- `jwt-tamper.aql` — verify failures > 10 per minute
- `container-escape.aql` — Falco T1611 event in any namespace
- `data-exfil-dns.aql` — high-entropy DNS subdomain to non-allow-list domain
- `fraud-ml.aql` — `fraud.alert` event AND amount > 100k

## 4. Offenses & Playbooks

| Offense | Auto-Response | Manual Step |
|---------|--------------|-------------|
| Cred stuffing | Add IP to denylist via OPA bundle update | Notify user, ask password reset |
| Container escape | Cordon node, kill pod | Forensic snapshot |
| Fraud ML | Freeze account, reverse transaction | Customer call-back |
