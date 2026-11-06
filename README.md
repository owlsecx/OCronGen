# 🦉 OCronGen

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Linux-0a0c10?style=flat-square"/>
  <img src="https://img.shields.io/badge/Category-Core%20/%20Utilities-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square"/>
  <img src="https://img.shields.io/badge/Part%20of-OwlSec%20Toolkit-7b5ea7?style=flat-square"/>
  <img src="https://img.shields.io/badge/Version-1.0-cyan?style=flat-square"/>
</p>

> **OCronGen** — Cron Builder/Validator/Explainer ║

---

> ⚠️ **AUTHORISED USE ONLY** — Use only on systems you own or have explicit written permission to test. Unauthorised use is illegal.

---

## 📌 Overview

OCronGen is a professional, offline-first Cron Builder/Validator/Explainer with an interactive cyan TUI and a full CLI (flag-based) supporting txt|md|json|csv|sarif exports, MITRE ATT&CK tagging on findings where meaningful, and A+..F posture grading.

---

## ✨ Features

- Build, explain and validate 5- and 6-field cron expressions plus @macros
- Quartz/Spring specials (L, W, #, ?) and next/prev run previews with timezone support
- Crontab file audit, lint, normalize, heatmap and inter-run gap stats
- Convert schedules to systemd OnCalendar, Kubernetes, GitHub Actions, Jenkins or AWS
- Named templates, DST risk checks and field-by-field expression diff
- Export reports as TXT, Markdown, JSON, CSV or SARIF 2.1.0

---

## ⚙️ Requirements

- **Linux**
- **Go 1.21+** (stdlib only; `CGO_ENABLED=0`)

---

## 🚀 Usage

```bash
go build -ldflags="-s -w" -o OCronGen OCronGen.go
./OCronGen --help
./OCronGen --expr "*/5 9-17 * * 1-5" --next 5
./OCronGen --template nightly-backup --format json
./OCronGen --crontab /etc/crontab --format sarif --output cron.sarif
```

---

## 📦 Part of OwlSec Toolkit

This tool is part of the **OwlSec** suite — a collection of 300+ security and privacy tools.

🔗 [owlsec.org](https://owlsec.org)

---

## ©️ License

MIT License — © Khaled S. Haddad
