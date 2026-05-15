# DomainXray — Domain Analysis Tool

Resolve DNS records across all major types, look up WHOIS registration data, and get everything in one unified report — available as a CLI tool, FastAPI server, or importable Python library.

## Features

- **DNS Lookup** — A, AAAA, CNAME, MX, NS, TXT, PTR, SRV records with batch queries
- **WHOIS Lookup** — Registrar, dates, name servers, status, emails across 80+ TLDs
- **Unified Inspection** — Get DNS + WHOIS in one call
- **Custom Resolvers** — Use Google DNS, Cloudflare, or any custom nameserver
- **WHOIS Referral Following** — Automatically follows referral chains for detailed results
- **Web UI** — Vue 3 + Tailwind dark-themed single-page interface
- **REST API** — FastAPI with auto-generated docs at `/docs`
- **JSON Output** — Machine-readable output for scripting and pipelines

## Tech Stack

| Component | Technology |
|-----------|------------|
| DNS | dnspython |
| WHOIS | Raw TCP socket (port 43) |
| CLI | argparse |
| API | FastAPI + Uvicorn |
| Frontend | Vue 3, Vite, Tailwind CSS |
| Deploy | Docker, Docker Compose |

## Quick Start

### Prerequisites

- Docker & Docker Compose

### 1. Clone

```bash
git clone <repo-url> && cd domainxray
```

### 2. Start with Docker Compose

```bash
docker compose up --build
```

- **App + API**: http://localhost:8000
- **API Docs**: http://localhost:8000/docs

## Local Development

### Backend

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn server:api --port 3000 --reload
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Open http://localhost:5173. The Vite dev server proxies `/api` requests to the backend on port 3000.

## Usage

### CLI

```bash
# Full scan (DNS + WHOIS)
python main.py google.com

# DNS only
python main.py google.com --dns-only

# Specific record types
python main.py google.com --dns-only -t A MX NS

# WHOIS only
python main.py google.com --whois-only

# Raw WHOIS response
python main.py google.com --whois-only --raw

# Custom DNS resolver
python main.py google.com --resolver 1.1.1.1

# JSON output
python main.py google.com --json
```

### API

```
GET /api/inspect?domain=google.com&resolver=1.1.1.1
GET /api/dns?domain=google.com&types=A,MX&resolver=1.1.1.1
GET /api/whois?domain=google.com
```

Interactive API docs at http://localhost:8000/docs.

### As a Library

```python
from app.inspector import DomainXray

xray = DomainXray()

report = xray.inspect("github.com")
dns    = xray.dns_only("github.com")
whois  = xray.whois_only("github.com")

print(report.to_json())
```

## Project Structure

```
domainxray/
├── app/                  # Core library
│   ├── models.py         # Data classes (DNSRecord, WhoisResult, DomainReport)
│   ├── dns_lookup.py     # DNS resolution engine (dnspython)
│   ├── whois_lookup.py   # WHOIS via raw TCP socket
│   └── inspector.py      # Unified DomainXray interface
├── main.py               # CLI entrypoint
├── server.py             # Web API + static frontend
├── frontend/             # Vue 3 + Vite + Tailwind SPA
│   ├── src/App.vue
│   └── dist/             # Production build (served by FastAPI)
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```
