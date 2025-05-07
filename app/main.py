from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel, HttpUrl, Field
from uuid import UUID, uuid4
from datetime import datetime
from typing import List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
import redis.asyncio as aioredis
import os

from db import get_scan_by_id, create_scan, get_scan_results, get_all_scans, async_session
from worker import start_scan_chain

app = FastAPI(title="ProjectDiscovery Security Scanner API")

class ScanRequest(BaseModel):
    target: HttpUrl
    nuclei_templates: List[str] = Field(default_factory=lambda: ["default"])

class ScanResponse(BaseModel):
    scan_id: UUID
    message: str

class ScanStatusResponse(BaseModel):
    scan_id: UUID
    target: HttpUrl
    status: str
    started_at: datetime
    finished_at: Optional[datetime]

class ScanResultsResponse(BaseModel):
    subdomains: List[str]
    urls: List[str]
    ports: List[dict]
    vulnerabilities: List[dict]

class ScanListItem(BaseModel):
    scan_id: UUID
    target: HttpUrl
    status: str
    started_at: datetime
    finished_at: Optional[datetime]

# Dependency for async DB session
async def get_async_session() -> AsyncSession:
    async with async_session() as session:
        yield session

# Dependency for async Redis client
async def get_redis():
    redis_url = os.getenv("CELERY_BROKER_URL", "redis://redis:6379/0")
    client = aioredis.from_url(redis_url)
    try:
        yield client
    finally:
        await client.close()

@app.post("/scans", response_model=ScanResponse)
async def create_scan_endpoint(request: ScanRequest):
    scan_id = uuid4()
    now = datetime.utcnow()
    await create_scan(scan_id, str(request.target), now)
    start_scan_chain.delay(str(scan_id), str(request.target), request.nuclei_templates)
    return ScanResponse(scan_id=scan_id, message="Scan started")

@app.get("/scans/{scan_id}", response_model=ScanStatusResponse)
async def get_scan_status(scan_id: UUID):
    scan = await get_scan_by_id(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan

@app.get("/scans/{scan_id}/results", response_model=ScanResultsResponse)
async def get_scan_results_endpoint(scan_id: UUID):
    results = await get_scan_results(scan_id)
    if not results:
        raise HTTPException(status_code=404, detail="Results not found")
    return results

@app.get("/scans", response_model=List[ScanListItem])
async def list_scans():
    scans = await get_all_scans()
    return scans 

@app.get("/health", status_code=200)
async def health_check(
    db: AsyncSession = Depends(get_async_session),
    redis = Depends(get_redis)
):
    """
    Health check endpoint to verify the API is running and its dependencies are accessible.
    Checks database and Redis connections.
    Returns a 200 OK status when all services are healthy, or a 503 Service Unavailable if any dependency is down.
    """
    health_status = {"status": "healthy", "services": {}}
    
    # Check database connection
    try:
        # Execute a simple query to verify database connection
        await db.execute(text("SELECT 1"))
        health_status["services"]["database"] = "up"
    except Exception as e:
        health_status["status"] = "unhealthy"
        health_status["services"]["database"] = f"down: {str(e)}"
    
    # Check Redis connection
    try:
        await redis.ping()
        health_status["services"]["redis"] = "up"
    except Exception as e:
        health_status["status"] = "unhealthy"
        health_status["services"]["redis"] = f"down: {str(e)}"
    
    if health_status["status"] == "unhealthy":
        raise HTTPException(status_code=503, detail=health_status)
        
    return health_status

