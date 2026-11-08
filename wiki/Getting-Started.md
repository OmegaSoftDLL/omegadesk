# Getting Started with OmegaDesk

## 1. Prerequisites

- **Rust Toolchain:** Rust `1.90` or newer (`rustup update`).
- **Windows:** Visual Studio C++ Build Tools (for Media Foundation, DXGI, and `OpenH264` bindings).
- **Web Gateway (Optional):** Node.js `22+` (`cd web && npm ci && npm run build`).

---

## 2. Mode A — Direct LAN Connection (By IP, Fingerprint & Password)

Start the agent on the host machine you want to access:

```sh
cargo run --release -p omegadesk-agent -- --listen 0.0.0.0:7070
```

The agent outputs its **TLS certificate fingerprint** and one-time **access password**. Connect from any client machine on the LAN:

```sh
cargo run --release -p omegadesk-client -- 192.168.0.10:7070 --fingerprint <fingerprint> --password <password>
```

---

## 3. Mode B — Self-Hosted Mesh Mode (`*.omega` Names, STUN/Disco & Relay)

1. **Start the Relay (`omegadesk-relay`):**
   ```sh
   cargo run --release -p omegadesk-relay -- --listen 0.0.0.0:8443 --ticket-secret-hex <64-hex-chars>
   ```
2. **Start the Coordinator (`omegadesk-server`):**
   ```sh
   cargo run --release -p omegadesk-server -- --listen 0.0.0.0:8080 --ticket-secret-hex <64-hex-chars> \
       --relay "relay.example:8443=<relay-pubkey>;stun=relay.example:8443"
   ```
3. **Enroll the Agent & Connect by Name (`office-pc.omega`):**
   ```sh
   cargo run --release -p omegadesk-agent -- --name office-pc --server coord.example:8080 --server-key <128-hex> --preauth-key odk_...
   cargo run --release -p omegadesk-client -- office-pc.omega --server coord.example:8080 --server-key <128-hex> --preauth-key odk_... --password <password>
   ```

---

## 4. Mode C — 9-Digit QuickSupport (`omegadesk-quicksupport`)

```sh
# End user runs:
cargo run --release -p omegadesk-quicksupport -- --server coord.example:8080 --server-key <128-hex> --preauth-key odk_<qs_key>
# Prints: Your ID: 123 456 789 | Password: abc123

# Technician connects:
cargo run --release -p omegadesk-client -- 123 456 789 --server coord.example:8080 --server-key <128-hex> --preauth-key odk_... --password abc123
```

---

## 5. Mode D — Windows Unattended `LocalSystem` Service

From an Administrator PowerShell prompt:

```powershell
omegadesk-agent service install
omegadesk-agent service start
```
