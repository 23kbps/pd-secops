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

### 5. Deploy to Kubernetes with Helm

```bash
# Create the namespace if it doesn't exist
kubectl create namespace pd-scanner

# Install the Helm chart into the pd-scanner namespace
helm install pd-scanner ./helm/pd-scanner -n pd-scanner

# Or upgrade if already installed
helm upgrade pd-scanner ./helm/pd-scanner -n pd-scanner
```

## Project Structure
- `app/` - FastAPI app, Celery worker, DB models
- `Dockerfile` - App image (includes ProjectDiscovery tools)
- `docker-compose.yml` - Multi-service orchestration

## Notes
- No authentication (MVP)
- All scan jobs are async and non-blocking
- Results are available after scan completion

## Architecture Overview

This app is designed for scalable, distributed security scanning using modern cloud-native patterns. It consists of the following main components:

- **FastAPI API**: Handles scan requests, status queries, and result retrieval. Async, stateless, and horizontally scalable.
- **Celery Workers**: Execute scan jobs in the background, running the ProjectDiscovery toolchain (subfinder → katana → naabu → nuclei). Scalable and distributed.
- **PostgreSQL**: Stores scan metadata, results, and vulnerabilities.
- **Redis**: Acts as the Celery broker and result backend.
- **ProjectDiscovery Tools**: Industry-standard binaries for subdomain discovery, crawling, port scanning, and vulnerability detection.
- **Kubernetes/Helm**: For scalable, production-grade deployment.

### High-Level Architecture Diagram

```
+---------+        +----------------+        +-----------------+
|  User   | <----> |   FastAPI API  | <----> |   PostgreSQL    |
+---------+        +----------------+        +-----------------+
                        |   ^
                        v   |
                 +----------------+
                 |   Redis (Broker)|
                 +----------------+
                        |
                        v
                 +----------------+
                 | Celery Workers |
                 +----------------+
                        |
                        v
         +-----------------------------------+
         | ProjectDiscovery Tools (subfinder, |
         | katana, naabu, nuclei)             |
         +-----------------------------------+
```

### Workflow

1. **User submits a scan request** via the API (`/scans`).
2. **API creates a scan record** in PostgreSQL and enqueues a background job in Redis (Celery broker).
3. **Celery worker picks up the job** and runs the scan chain:
    - **subfinder**: Finds subdomains.
    - **katana**: Crawls for URLs.
    - **naabu**: Scans for open ports.
    - **nuclei**: Runs vulnerability templates.
4. **Each stage stores results** in PostgreSQL as it completes.
5. **User can query scan status** (`/scans/{scan_id}`) or **fetch results** (`/scans/{scan_id}/results`) at any time.
6. **Kubernetes/Helm** enables scaling of API and worker pods independently for high throughput and reliability.

---

MIT License 