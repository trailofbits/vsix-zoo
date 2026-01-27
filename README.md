# vsix-zoo

> **WARNING: This repository contains live malware samples for security research purposes. Do not execute, install, or open these files outside of an isolated analysis environment. Handle with extreme caution.**

Malware sample collection for [vsix-audit](https://github.com/trailofbits/vsix-audit) security scanner testing.

## Purpose

- Validate scanner detection capabilities
- Share threat intelligence with the security community
- Track emerging threats targeting developers

## Samples

| Directory | Description | Capabilities |
|-----------|-------------|--------------|
| `apollyon/` | Discord webhook exfil PoC | data-exfiltration, crypto-wallet |
| `doyensec/` | VS Code security research | workspace trust bypass |
| `ecm3401/` | Educational attack suite | ssh-theft, docker-tampering, RCE |
| `glassworm/` | Supply chain malware (Rust implants) | credential-theft, crypto-wallet, VNC |
| `kagema/` | SnowShoNo downloader | obfuscation, powershell-execution |
| `kirill89/` | Workspace trust exploit demos | code execution via tasks/extensions |
| `malwarebazaar/` | GlassWorm artifacts from MalwareBazaar | loader, native-code-execution |
| `nextsecurity/` | Malicious CSS/LESS stylesheets | data exfiltration via CSS |
| `nf3xn/` | Educational malicious extension | basic malicious extension |
| `securezeron/` | Reverse shell PoC | reverse-shell, RCE |
| `snyk-labs/` | VS Code extension exploit demo | credential-theft via webview |

See `manifest.json` for full metadata including hashes, sources, and campaign attribution.

## Usage with vsix-audit

```bash
# Clone this repo alongside vsix-audit
git clone git@github.com:trailofbits/vsix-zoo.git
git clone git@github.com:trailofbits/vsix-audit.git

# Run tests with samples
cd vsix-audit
VSIX_ZOO_PATH=../vsix-zoo/samples npm test
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to submit samples.

