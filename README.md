# 🛡️ Minimal API-Based Security Scanner

A simple, API-driven web service to initiate and track security scanning jobs for a given domain. Uses ProjectDiscovery tools (`subfinder`, `katana`, `naabu`, `nuclei`) in a Celery-powered background task chain. Results are stored in PostgreSQL and accessible via API.

## Features
- Async REST API (FastAPI)
- Background scan jobs (Celery + Redis)
- Results and metadata in PostgreSQL
- Dockerized for local development

## Quickstart

### 1. Clone and Build
```bash
git clone <repo-url>
cd pd-secops
docker-compose up --build
```

### 2. Run Database Migrations
In a new terminal:
```bash
docker-compose exec api alembic upgrade head
```

### 3. Access the API
- Swagger UI: [http://localhost:8000/docs](http://localhost:8000/docs)

### 4. Example Usage
#### Start a Scan
```bash
curl -X POST http://localhost:8000/scans \
  -H 'Content-Type: application/json' \
  -d '{"target": "example.com", "nuclei_templates": ["cves", "default"]}'
```
#### Get Scan Status
```bash
curl http://localhost:8000/scans/<scan_id>
```
#### Get Scan Results
```bash
curl http://localhost:8000/scans/<scan_id>/results
```

## Project Structure
- `app/` - FastAPI app, Celery worker, DB models
- `Dockerfile` - App image (includes ProjectDiscovery tools)
- `docker-compose.yml` - Multi-service orchestration

## Notes
- No authentication (MVP)
- All scan jobs are async and non-blocking
- Results are available after scan completion

---

MIT License 