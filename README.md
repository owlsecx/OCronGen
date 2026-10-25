# 🦉 OCronGen

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Linux-0a0c10?style=flat-square"/>
  <img src="https://img.shields.io/badge/Category-Security-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square"/>
  <img src="https://img.shields.io/badge/Part%20of-OwlSec%20Toolkit-7b5ea7?style=flat-square"/>
  <img src="https://img.shields.io/badge/Version-1.0-cyan?style=flat-square"/>
</p>

> **OCronGen** — part of the OwlSec Toolkit.

---

> ⚠️ **AUTHORISED USE ONLY** — Use only on systems you own or have explicit written permission to test. Unauthorised use is illegal.

---

## 📌 Overview

OCronGen makes cron schedules easy to read and safe to deploy. It parses any cron expression, including ranges, steps, names, @presets and 6-field expressions with seconds, explains it in plain English and previews when it will run next. It also audits whole crontab files for syntax errors and risky jobs.

---

## ✨ Features

- Full cron parser with correct day-of-month / day-of-week OR semantics and 6-field (seconds) support
- Plain-English explanation of any schedule and a next-run preview with average interval
- Interactive builder from minute / hour / day choices
- Crontab linter: bad syntax, PATH/SHELL issues, curl|sh, world-writable scripts, root jobs, very frequent jobs, @reboot
- Converts a schedule to a systemd OnCalendar timer
- Reports in TXT / JSON / Markdown / CSV / SARIF; --audit exits with code 3 on HIGH/CRITICAL findings

---

## ⚙️ Requirements

- **Linux**
- **No Python installation needed** — runs as a standalone executable

---

## 🚀 Usage

```bash
./OCronGen                                   # interactive menu
./OCronGen --explain "*/15 9-17 * * mon-fri"
./OCronGen --next "0 3 * * *" -n 10
./OCronGen --audit /etc/crontab --system
./OCronGen --oncalendar "30 2 * * sun"
```

Run `./OCronGen --help` for the full list of options.

---

## 📦 Part of OwlSec Toolkit

This tool is part of the **OwlSec** suite — a collection of 300+ security and privacy tools.

🔗 [owlsec.org](https://owlsec.org)

---

## ©️ License

MIT License — © Khaled S. Haddad

*Tools are distributed as pre-built executables. Source code is proprietary.*
