# vsix-zoo

> **WARNING: This repository contains live malware samples for security research purposes. Do not execute, install, or open these files outside of an isolated analysis environment. Handle with extreme caution.**

Malware sample collection for [vsix-audit](https://github.com/trailofbits/vsix-audit) security scanner testing.

## Purpose

- Validate scanner detection capabilities
- Share threat intelligence with the security community
- Track emerging threats targeting developers

## Directory Structure

```
vsix-zoo/
├── samples/                # Malicious extensions (VSIX files or extracted folders)
│   ├── apollyon/           # Discord webhook exfil PoC
│   ├── ecm3401/            # Educational attack suite
│   ├── glassworm/          # Supply chain malware
│   ├── kagema/             # SnowShoNo samples
│   └── ...
├── manifest.json           # Sample metadata/index
├── watchlist/              # Suspicious extensions to monitor
└── research/               # Threat intelligence notes
```

## Threat Actors Tracked

| Actor | Campaign | Targets | Active |
|-------|----------|---------|--------|
| GlassWorm | Supply chain | All developers | Yes |
| WhiteCobra | Crypto theft | Crypto developers | Yes |
| TigerJack | Code theft, mining | All developers | Yes |
| FAMOUS CHOLLIMA | Interview scams | Job seekers | Yes |
| Unknown | Evelyn Stealer | Crypto developers | Yes |

## Usage with vsix-audit

```bash
# Clone this repo alongside vsix-audit
git clone git@github.com:trailofbits/vsix-zoo.git
git clone git@github.com:trailofbits/vsix-audit.git

# Run tests with samples
cd vsix-audit
VSIX_ZOO_PATH=../vsix-zoo/samples npm test
```

## Sample Sources

### GitHub Repositories

| Repository | Contents |
|------------|----------|
| [b4ba/ECM3401-VSCode-Extensions](https://github.com/b4ba/ECM3401-VSCode-Extensions) | Pre-built .vsix files (educational) |
| [KagemaNjoroge/malicious-vscode-extensions](https://github.com/KagemaNjoroge/malicious-vscode-extensions) | Community tracker with extension folders |
| [0x-Apollyon/Malicious-VScode-Extension](https://github.com/0x-Apollyon/Malicious-VScode-Extension) | PoC samples |

### VirusTotal Hashes

| Sample | SHA256 | Campaign |
|--------|--------|----------|
| os.node (Windows) | `6ebeb188f3cc3b647c4460c0b8e41b75d057747c662f4cd7912d77deaccfd2f2` | GlassWorm |
| darwin.node (macOS) | `fb07743d139f72fca4616b01308f1f705f02fda72988027bc68e9316655eadda` | GlassWorm |
| extension.js | `9212a99a7730b9ee306e804af358955c3104e5afce23f7d5a207374482ab2f8f` | GlassWorm |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to submit samples.

## Legal Notice

This collection is for **security research and defensive tool development only**.

- Do NOT execute samples outside isolated/sandboxed environments
- Do NOT use samples for malicious purposes
- Samples may be subject to takedown requests

## Related Projects

- [vsix-audit](https://github.com/trailofbits/vsix-audit) - VS Code extension security scanner
- [Knostic GlassWorm YARA](https://github.com/knostic/open-tools/tree/main/glassworm_yara) - Detection rules
- [Koi Security](https://dex.koi.security/) - Extension threat intelligence
