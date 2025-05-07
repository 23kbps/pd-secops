from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse
from pydantic import BaseModel, HttpUrl, Field
from uuid import UUID, uuid4
from datetime import datetime
from typing import List, Optional

from db import get_scan_by_id, create_scan, get_scan_results, get_all_scans
from worker import start_scan_chain

app = FastAPI(title="Minimal Security Scanner API")

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