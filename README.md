# prometheus-alertmanager-grafana-rules-cli-lite

![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)
![Zero Dependencies](https://img.shields.io/badge/dependencies-zero%20(stdlib%20only)-brightgreen.svg)
![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)

**Offline, zero-dependency Python 3.9+ CLI linter for Prometheus alert rule YAML files and Alertmanager routing configurations.**

**Офлайн-линтер на чистом Python 3.9+ (без внешних зависимостей) для YAML-правил алертинга Prometheus и конфигураций маршрутизации Alertmanager.**

---

## Features / Возможности

- **100% Pure Python Stdlib:** Built-in lightweight YAML parser (`yaml_lite.py`), no `PyYAML` or third-party packages required.
- **Prometheus Alert Rules:** Detects missing `for:` (flapping alerts), missing `severity` label, missing `summary`/`runbook_url` annotations, fragile `== 0` comparisons, short `rate()`/`irate()`/`increase()` windows (`< 2m`), and duplicate alert names.
- **Alertmanager Configs:** Detects missing `group_by`/`repeat_interval` on root routes, unreferenced or undefined receivers, and hardcoded webhook/API secrets.
- **CI-Ready Outputs:** Supports `text`, `json`, and `markdown` output formats with `--fail-on` severity thresholds (`none`, `info`, `warning`, `error`, `critical`).

---

## Quick Start / Быстрый старт

```bash
# Lint a single file (text output)
python -m prom_alert_lint samples/prometheus-rules-broken.yml

# Lint a directory with JSON output and fail on warnings
python -m prom_alert_lint samples/ --format json --fail-on warning

# Generate Markdown report for PR comments
python -m prom_alert_lint samples/alertmanager-broken.yml --format markdown --fail-on critical
```

---

## Lint Rules / Таблица правил

| Rule ID | Severity | Target | Description (EN / RU) |
| --- | --- | --- | --- |
| `PROM001` | `warning` | Prometheus | Missing `for:` duration (flapping alerts) / Отсутствует `for:` (дребезг алертов) |
| `PROM002` | `error` | Prometheus | Missing `labels.severity` / Отсутствует обязательный лейбл `severity` |
| `PROM003` | `warning` | Prometheus | Missing `summary` or `runbook_url` annotation / Нет `summary` или `runbook_url` |
| `PROM004` | `warning` | Prometheus | Fragile `== 0` comparison in `expr` / Хрупкое сравнение `== 0` в `expr` |
| `PROM005` | `warning` | Prometheus | `rate()`/`irate()`/`increase()` window `< 2m` / Слишком короткое окно `< 2m` |
| `PROM006` | `error` | Prometheus | Duplicate alert name across groups/files / Дублирующееся имя алерта |
| `AM001` | `warning` | Alertmanager | Root route missing `group_by` or `repeat_interval` / Нет `group_by` или `repeat_interval` |
| `AM002` | `error` | Alertmanager | Unreferenced or undefined receiver / Неиспользуемый или неопределённый receiver |
| `AM003` | `critical` | Alertmanager | Hardcoded webhook/API secret in receiver / Захардкоженный секрет или токен |

---

## Running Tests / Запуск тестов

```bash
python -m unittest discover -s tests -v
```

---

## Need the full Pro Studio (Web UI, PromQL expression audit, Grafana JSON check, SARIF 2.1.0, diff mode)?

Get the full **Pro Studio** edition on FunPay:  
👉 **https://funpay.com/users/20096179/**
