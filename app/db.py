import os
from uuid import UUID
from datetime import datetime
from typing import List, Optional
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import declarative_base, relationship
from sqlalchemy import Column, String, DateTime, Text, Integer, ForeignKey, Enum
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
import enum
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload

DATABASE_URL = os.getenv("DATABASE_URL")

engine = create_async_engine(DATABASE_URL, echo=False, future=True)
async_session = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
Base = declarative_base()

class ScanStatusEnum(str, enum.Enum):
    in_progress = "in_progress"
    completed = "completed"
    failed = "failed"

class Scan(Base):
    __tablename__ = "scans"
    scan_id = Column(PG_UUID(as_uuid=True), primary_key=True)
    target = Column(Text, nullable=False)
    status = Column(String, default=ScanStatusEnum.in_progress, nullable=False)
    started_at = Column(DateTime, nullable=False)
    finished_at = Column(DateTime, nullable=True)
    subdomains = relationship("Subdomain", back_populates="scan")
    urls = relationship("URL", back_populates="scan")
    ports = relationship("Port", back_populates="scan")
    vulnerabilities = relationship("Vulnerability", back_populates="scan")

class Subdomain(Base):
    __tablename__ = "subdomains"
    id = Column(Integer, primary_key=True)
    scan_id = Column(PG_UUID(as_uuid=True), ForeignKey("scans.scan_id"))
    subdomain = Column(Text, nullable=False)
    scan = relationship("Scan", back_populates="subdomains")

class URL(Base):
    __tablename__ = "urls"
    id = Column(Integer, primary_key=True)
    scan_id = Column(PG_UUID(as_uuid=True), ForeignKey("scans.scan_id"))
    url = Column(Text, nullable=False)
    scan = relationship("Scan", back_populates="urls")

class Port(Base):
    __tablename__ = "ports"
    id = Column(Integer, primary_key=True)
    scan_id = Column(PG_UUID(as_uuid=True), ForeignKey("scans.scan_id"))
    ip = Column(Text, nullable=False)
    port = Column(Integer, nullable=False)
    scan = relationship("Scan", back_populates="ports")

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    id = Column(Integer, primary_key=True)
    scan_id = Column(PG_UUID(as_uuid=True), ForeignKey("scans.scan_id"))
    template_id = Column(Text, nullable=False)
    severity = Column(String, nullable=False)
    matched_url = Column(Text, nullable=False)
    description = Column(Text, nullable=False)
    scan = relationship("Scan", back_populates="vulnerabilities")

# --- CRUD Functions ---
async def create_scan(scan_id: UUID, target: str, started_at: datetime):
    async with async_session() as session:
        scan = Scan(scan_id=scan_id, target=target, started_at=started_at, status=ScanStatusEnum.in_progress)
        session.add(scan)
        await session.commit()

async def update_scan_status(scan_id: UUID, status: str, finished_at: Optional[datetime] = None):
    async with async_session() as session:
        scan = await session.get(Scan, scan_id)
        if scan:
            scan.status = status
            scan.finished_at = finished_at
            await session.commit()

async def get_scan_by_id(scan_id: UUID):
    async with async_session() as session:
        scan = await session.get(Scan, scan_id)
        if not scan:
            return None
        return {
            "scan_id": scan.scan_id,
            "target": scan.target,
            "status": scan.status,
            "started_at": scan.started_at,
            "finished_at": scan.finished_at,
        }

async def add_subdomains(scan_id: UUID, subdomains: List[str]):
    async with async_session() as session:
        objs = [Subdomain(scan_id=scan_id, subdomain=s) for s in subdomains]
        session.add_all(objs)
        await session.commit()

async def add_urls(scan_id: UUID, urls: List[str]):
    async with async_session() as session:
        objs = [URL(scan_id=scan_id, url=u) for u in urls]
        session.add_all(objs)
        await session.commit()

async def add_ports(scan_id: UUID, ports: List[dict]):
    async with async_session() as session:
        objs = [Port(scan_id=scan_id, ip=p["ip"], port=p["port"]) for p in ports]
        session.add_all(objs)
        await session.commit()

async def add_vulnerabilities(scan_id: UUID, vulns: List[dict]):
    async with async_session() as session:
        objs = [Vulnerability(scan_id=scan_id, **v) for v in vulns]
        session.add_all(objs)
        await session.commit()

async def get_scan_results(scan_id: UUID):
    async with async_session() as session:
        result = await session.execute(
            select(Scan)
            .options(
                selectinload(Scan.subdomains),
                selectinload(Scan.urls),
                selectinload(Scan.ports),
                selectinload(Scan.vulnerabilities),
            )
            .where(Scan.scan_id == scan_id)
        )
        scan = result.scalar_one_or_none()
        if not scan:
            return None
        subdomains = [s.subdomain for s in scan.subdomains]
        urls = [u.url for u in scan.urls]
        ports = [{"ip": p.ip, "port": p.port} for p in scan.ports]
        vulnerabilities = [
            {
                "template_id": v.template_id,
                "severity": v.severity,
                "matched_url": v.matched_url,
                "description": v.description,
            }
            for v in scan.vulnerabilities
        ]
        return {
            "subdomains": subdomains,
            "urls": urls,
            "ports": ports,
            "vulnerabilities": vulnerabilities,
        }

async def get_all_scans():
    async with async_session() as session:
        result = await session.execute(
            Scan.__table__.select().order_by(Scan.started_at.desc())
        )
        scans = result.fetchall()
        return [
            {
                "scan_id": row.scan_id,
                "target": row.target,
                "status": row.status,
                "started_at": row.started_at,
                "finished_at": row.finished_at,
            }
            for row in scans
        ]

# --- DB Init ---
async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all) 