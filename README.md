# OpenCred Releases

This repository hosts **public release artefacts** for [OpenCred](https://docs.opencred.global) — a local-first platform for issuing and verifying W3C Verifiable Credentials, published by [NFH Trust Labs](https://github.com/nfh-trust-labs).

> **Looking for source code or issues?** This repo contains binaries only. Source code lives in the private `nfh-trust-labs/opencred` repo. To file a bug, request a feature, or contribute, reach out via the contact details on https://docs.opencred.global.

## What's here

Each tagged release publishes:

| Artefact | Format | Audience |
|---|---|---|
| `OpenCred-<version>.dmg` | macOS installer (Intel + Apple Silicon) | Desktop users on macOS |
| `OpenCred-<version>.AppImage` | Linux portable binary | Desktop users on Linux |
| `OpenCred-<version>.deb` | Debian / Ubuntu package | Desktop users on Linux |
| `latest-mac.yml`, `latest-linux.yml` | Auto-updater manifests | Internal — used by electron-updater |
| `*.blockmap` | Differential update blockmaps | Internal — used by electron-updater |
| `SHA256SUMS` | Checksums for all artefacts | Anyone verifying download integrity |

> **Windows builds are not currently shipped.** Tracked in the source repo.

The Docker server image is published separately to **GitHub Container Registry**:

```
ghcr.io/nfh-trust-labs/opencred/opencred-server:<version>
ghcr.io/nfh-trust-labs/opencred/opencred-server:latest
```

Pull with:

```bash
docker pull ghcr.io/nfh-trust-labs/opencred/opencred-server:latest
```

No GHCR authentication is required — the image is public.

## Verifying downloads

Every release includes a `SHA256SUMS` file. After downloading, verify integrity:

```bash
sha256sum -c SHA256SUMS --ignore-missing
```

On macOS use `shasum -a 256 -c` instead.

## Auto-updates

The Desktop Client auto-updates from this repository via [electron-updater](https://www.electron.build/auto-update). No action is required from end users — once installed, OpenCred polls for new releases and prompts to install.

To opt out, disable auto-updates in **Settings → Updates** within the app.

## Documentation

- **End-user guide**: https://docs.opencred.global
- **Bootcamp**: https://docs.opencred.global/bootcamp
- **Docker operator guide**: https://docs.opencred.global/docker
- **Security model**: https://docs.opencred.global/security

## Support

OpenCred is published by NFH Trust Labs. For commercial deployments, integration support, or custom builds, see https://docs.opencred.global for contact information.

## Licensing

OpenCred binaries distributed via this repository are made available under the terms specified in [`NOTICE.md`](./NOTICE.md). The OpenCred source code is **not** open-source — redistribution, modification, or reverse engineering is not permitted without prior written permission from NFH Trust Labs.

A formal end-user licence agreement (EULA) will be published before the first commercial / regulated adopter ships in production. Until then, use is permitted for evaluation, development, and bootcamp / workshop scenarios.

---

*This repository is a distribution mirror. Pushes here are automated by CI in the source repo and should not be made manually.*
