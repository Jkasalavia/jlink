# JKELTS LINK DISCOVERY

Windows LLDP/CDP switch-port discovery helper for IT support.

Live page:

```text
https://jkasalavia.github.io/jlink/
```

Run:

```powershell
irm https://jkasalavia.github.io/jlink/r|iex
```

Notes:

- Requires Administrator rights.
- Uses PSDiscoveryProtocol first.
- Can install PSDiscoveryProtocol from PowerShell Gallery when missing.
- TShark/Wireshark is used only as fallback when available.
- Browser apps cannot capture LLDP/CDP Layer 2 packets directly.
