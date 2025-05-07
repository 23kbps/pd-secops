import os
from uuid import UUID
from datetime import datetime
from typing import List, Optional
from sqlalchemy import create_engine, Column, String, DateTime, Text, Integer, ForeignKey, Enum
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
import enum

DATABASE_URL = os.getenv("DATABASE_URL_SYNC", os.getenv("DATABASE_URL").replace("+asyncpg", ""))

engine = create_engine(DATABASE_URL, echo=False, future=True)
SessionLocal = sessionmaker(bind=engine)
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

def add_subdomains(scan_id: UUID, subdomains: List[str]):
    with SessionLocal() as session:
        objs = [Subdomain(scan_id=scan_id, subdomain=s) for s in subdomains]
        session.add_all(objs)
        session.commit()

def add_urls(scan_id: UUID, urls: List[str]):
    with SessionLocal() as session:
        objs = [URL(scan_id=scan_id, url=u) for u in urls]
        session.add_all(objs)
        session.commit()

def add_ports(scan_id: UUID, ports: List[dict]):
    with SessionLocal() as session:
        objs = [Port(scan_id=scan_id, ip=p["ip"], port=p["port"]) for p in ports]
        session.add_all(objs)
        session.commit()

def add_vulnerabilities(scan_id: UUID, vulns: List[dict]):
    with SessionLocal() as session:
        objs = [Vulnerability(scan_id=scan_id, **v) for v in vulns]
        session.add_all(objs)
        session.commit()

def update_scan_status(scan_id: UUID, status: str, finished_at: Optional[datetime] = None):
    with SessionLocal() as session:
        scan = session.get(Scan, scan_id)
        if scan:
            scan.status = status
            scan.finished_at = finished_at
            session.commit() 