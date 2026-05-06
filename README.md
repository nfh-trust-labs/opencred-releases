# OpenCred Releases

This repository hosts release artefacts for [**OpenCred**](https://opencred.gitbook.io/docs) — a local-first platform for issuing and verifying W3C Verifiable Credentials, published by [NFH Trust Labs](https://github.com/nfh-trust-labs).

> **🧪 Beta release.** OpenCred is in early-access beta. Functionality is feature-complete and the protocols are stable; some platform polish (Windows installers, code-signing, auto-update on macOS) is still in progress.
>
> **Bug reports and feature requests:** [open an issue](https://github.com/nfh-trust-labs/opencred-releases/issues) and a maintainer will respond.

## What's here

Each tagged release publishes:

| Artefact | Format | Audience |
|---|---|---|
| `OpenCred-<version>.dmg` | macOS installer (Intel + Apple Silicon) | Desktop users on macOS |
| `OpenCred-<version>.AppImage` | Linux portable binary | Desktop users on Linux |
| `OpenCred-<version>.deb` | Debian / Ubuntu package | Desktop users on Linux |
| `latest-mac.yml`, `latest-linux.yml` | Auto-updater manifests | Used by electron-updater |
| `*.blockmap` | Differential update blockmaps | Used by electron-updater |
| `SHA256SUMS` | Checksums for all artefacts | Anyone verifying download integrity |

Windows installers will be added in a later beta.

The Docker server image is published separately to **GitHub Container Registry**:

```
ghcr.io/nfh-trust-labs/opencred/opencred-server:<version>
ghcr.io/nfh-trust-labs/opencred/opencred-server:latest
```

Pull with:

```bash
docker pull ghcr.io/nfh-trust-labs/opencred/opencred-server:latest
```

The image is multi-architecture (`linux/amd64` + `linux/arm64`) and public — no GHCR authentication is required. Apple Silicon Macs, AWS Graviton, Raspberry Pi, and standard amd64 cloud VMs all pull the right variant automatically.

## Verifying downloads

Every release includes a `SHA256SUMS` file. After downloading, verify integrity:

```bash
sha256sum -c SHA256SUMS --ignore-missing
```

On macOS use `shasum -a 256 -c` instead.

## macOS first-launch

The first time you open OpenCred on macOS, you'll see a one-time security prompt: *"OpenCred cannot be opened because the developer cannot be verified."* This is expected during the beta — to allow the app to launch:

1. Open **Finder → Applications**.
2. **Right-click** (or Ctrl-click) on `OpenCred.app` and choose **Open**.
3. In the confirmation dialog, click **Open** again.
4. macOS remembers the approval. Every subsequent launch is normal.

If you instead see *"OpenCred is damaged and can't be opened"*, the download picked up an extra quarantine attribute. Clear it from Terminal and retry:

```bash
xattr -cr /Applications/OpenCred.app
open /Applications/OpenCred.app
```

## Auto-updates

The Desktop Client polls this repository for new versions via [electron-updater](https://www.electron.build/auto-update).

> **During the beta, auto-update is disabled on macOS.** Re-download new versions manually from this page when notified, using the same approval steps above.

To opt out of auto-updates entirely once they're enabled, disable them in **Settings → Updates** within the app.

## Documentation

Full documentation — installation guides, API reference, the bootcamp walkthrough, and the security model — lives at:

👉 **<https://opencred.gitbook.io/docs>**

## Support

- **Bug reports / feature requests:** [open an issue](https://github.com/nfh-trust-labs/opencred-releases/issues)
- **Documentation:** <https://opencred.gitbook.io/docs>

## Licensing

OpenCred binaries distributed via this repository are made available under the terms specified in [`NOTICE.md`](./NOTICE.md). A formal end-user licence agreement (EULA) will be published before the first commercial / regulated production deployment.

---

*This repository is a distribution mirror. Releases are published automatically by CI on every tagged version.*
