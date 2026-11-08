# Self-Hosting Relay, Coordinator & Fleet RMM

## 1. Deploying `omegadesk-relay` and `omegadesk-server`

Generate a shared 32-byte hex secret (`64` hex characters) for relay ticket authentication:

```sh
# 1. Start the STUN + DERP Packet Relay
omegadesk-relay --listen 0.0.0.0:8443 --ticket-secret-hex <64-hex>

# 2. Start the Coordinator, WebCodecs Gateway & Local RMM Admin API
omegadesk-server \
  --listen 0.0.0.0:8080 \
  --ticket-secret-hex <64-hex> \
  --relay "relay.example:8443=<relay-pubkey>;stun=relay.example:8443" \
  --policy policy.hujson \
  --state-file omegadesk-state.json \
  --audit-log omegadesk-audit.jsonl \
  --web-listen 127.0.0.1:18123
```

---

## 2. Operating the Built-In Fleet RMM (`omegadesk-server admin`)

Every enrolled mesh agent automatically reports hardware, OS, storage, network, and process inventory at startup, every 15 minutes, and on state change:

```sh
export OMEGADESK_ADMIN_TOKEN=<admin_token>

# Inspect fleet status, CPU/RAM/disk metrics, and active alerts
omegadesk-server admin devices
omegadesk-server admin device show office-pc

# Configure automated threshold alerts
omegadesk-server admin checks add --id disk-c --kind disk --target 'C:' --max-percent 85 --tenant default --severity critical

# Register, run, and schedule remote PowerShell / sh / cmd scripts
omegadesk-server admin scripts add --name "Clean temp" --shell powershell --file clean.ps1
omegadesk-server admin run office-pc --script clean-temp
omegadesk-server admin schedules add --name "Nightly" --tenant default --script clean-temp --interval daily --site hq

# Generate expiring zero-touch deployment links (odl_...)
omegadesk-server admin links create --tenant default --site hq --expires-in 86400
```
