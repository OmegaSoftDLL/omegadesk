# WireGuard Mesh & Zero-Trust Security

## 1. Identity-Bound Mesh Networking (`omegadesk-magicsock`)

In mesh mode, every node generates an Ed25519 identity keypair and X25519 static keypair stored in the OS keychain:
- **Discovery:** Nodes query STUN on `omegadesk-relay` and exchange encrypted `disco` probes to establish direct peer-to-peer UDP paths across NATs.
- **1.5-Second DERP Relay Fallback:** If direct hole punching has not validated within `1.5 s`, traffic flows immediately through `omegadesk-relay` using single-use coordinator tickets while background `disco` probes continue upgrading to a direct path.
- **Identity-Bound QUIC TLS 1.3:** The QUIC TLS handshake verifies that the peer's certificate matches the exact Ed25519 key distributed in the coordinator's signed netmap.

---

## 2. `HuJSON` Zero-Trust Policy Engine (`policy/v2`)

Start `omegadesk-server --policy policy.hujson` to enforce fine-grained access control, step-up MFA, DLP, and session recording:

```hujson
{
  "groups": { "group:helpdesk": ["alice@example.com"] },
  "tagOwners": { "tag:servers": ["group:helpdesk"] },
  "sessions": [
    {
      "action": "check",
      "src": ["group:helpdesk", "tag:helpdesk"],
      "dst": ["tag:servers"],
      "record": true,
      "clipboard": { "copy": 65536, "paste": 0 },
      "watermark": true,
      "posture": { "minOs": { "windows": "10.0.19045" }, "networks": ["100.64.0.0/10"] }
    }
  ]
}
```

- **Netmap Filtering:** Nodes excluded by policy never receive the target peer in their netmap (zero network visibility).
- **Per-Session TOTP MFA (`"action": "check"`):** Enforces RFC 6238 HMAC-SHA256 6-digit TOTP codes (`--totp-secret` / `--generate-totp-secret`) with brute-force lockout.
- **Session Recording (`.odrec`) & Watermark:** Automatically records sessions marked `"record": true` to `--recordings-dir` and overlays live operator attribution (`user | client IP | session | time`) into the video stream.
