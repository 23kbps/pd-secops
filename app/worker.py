import os
import subprocess
import json
import asyncio
import logging
from urllib.parse import urlparse
from celery import Celery, chain
from db import (
    add_subdomains, add_urls, add_ports, add_vulnerabilities,
    update_scan_status
)
from datetime import datetime
from uuid import UUID

CELERY_BROKER_URL = os.getenv("CELERY_BROKER_URL", "redis://redis:6379/0")
CELERY_RESULT_BACKEND = os.getenv("CELERY_RESULT_BACKEND", "redis://redis:6379/0")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

celery_app = Celery(
    "worker",
    broker=CELERY_BROKER_URL,
    backend=CELERY_RESULT_BACKEND,
)

def run_async(coro):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()

def ensure_url(target: str) -> str:
    if target.startswith("http://") or target.startswith("https://"):
        return target
    return f"https://{target}"

def strip_scheme(target: str) -> str:
    parsed = urlparse(target)
    if parsed.scheme:
        host = parsed.netloc or parsed.path
    else:
        host = target
    # Remove any trailing slashes
    return host.rstrip('/')

@celery_app.task(bind=True)
def subfinder_task(self, scan_id: str, target: str):
    try:
        domain = strip_scheme(target)
        logger.info(f"subfinder input: {repr(target)} -> {repr(domain)}")
        result = subprocess.run([
            "subfinder", "-d", domain, "-silent", "-oJ"
        ], capture_output=True, text=True, check=True)
        subdomains = [json.loads(line)["host"] for line in result.stdout.splitlines() if line.strip()]
        run_async(add_subdomains(UUID(scan_id), subdomains))
        return {"subdomains": subdomains}
    except Exception as e:
        logger.exception("Error in subfinder_task")
        run_async(update_scan_status(UUID(scan_id), "failed", datetime.utcnow()))
        raise e

@celery_app.task(bind=True)
def katana_task(self, prev_result, scan_id: str, target: str):
    try:
        url = ensure_url(target)
        logger.info(f"katana input: {repr(target)} -> {repr(url)}")
        result = subprocess.run([
            "katana", "-u", url, "-silent", "-jsonl"
        ], capture_output=True, text=True, check=True)
        logger.info(f"katana raw output: {result.stdout}")
        urls = []
        for line in result.stdout.splitlines():
            if line.strip():
                try:
                    j = json.loads(line)
                    if "url" in j:
                        urls.append(j["url"])
                except Exception as ex:
                    logger.warning(f"Could not parse katana line: {line} ({ex})")
        run_async(add_urls(UUID(scan_id), urls))
        return {**prev_result, "urls": urls}
    except Exception as e:
        logger.exception("Error in katana_task")
        run_async(update_scan_status(UUID(scan_id), "failed", datetime.utcnow()))
        raise e

@celery_app.task(bind=True)
def naabu_task(self, prev_result, scan_id: str, target: str):
    try:
        subdomains = prev_result.get("subdomains", [])
        hosts = subdomains if subdomains else [strip_scheme(target)]
        logger.info(f"naabu input hosts: {hosts}")
        logger.info(f"naabu command: naabu -silent -json, input: {'|'.join(hosts)}")
        result = subprocess.run(
            ["naabu", "-silent", "-json"],
            input="\n".join(hosts),
            text=True,
            capture_output=True,
            check=True
        )
        logger.info(f"naabu raw output: {result.stdout}")
        ports = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
        run_async(add_ports(UUID(scan_id), ports))
        return {**prev_result, "ports": ports}
    except Exception as e:
        logger.exception("Error in naabu_task")
        run_async(update_scan_status(UUID(scan_id), "failed", datetime.utcnow()))
        raise e

@celery_app.task(bind=True)
def nuclei_task(self, prev_result, scan_id: str, target: str, nuclei_templates):
    try:
        subdomains = prev_result.get("subdomains", [])
        targets = subdomains if subdomains else [ensure_url(target)]
        logger.info(f"nuclei input targets: {targets}")
        templates_args = []
        for t in nuclei_templates:
            templates_args.extend(["-tl", t])
        result = subprocess.run([
            "nuclei", "-list", "-", "-jsonl"] + templates_args,
            input="\n".join(targets),
            text=True,
            capture_output=True,
            check=True
        )
        logger.info(f"nuclei raw output: {result.stdout}")
        vulns = []
        for line in result.stdout.splitlines():
            if line.strip():
                j = json.loads(line)
                vulns.append({
                    "template_id": j.get("templateID", ""),
                    "severity": j.get("info", {}).get("severity", "unknown"),
                    "matched_url": j.get("matched", ""),
                    "description": j.get("info", {}).get("name", "")
                })
        run_async(add_vulnerabilities(UUID(scan_id), vulns))
        run_async(update_scan_status(UUID(scan_id), "completed", datetime.utcnow()))
        return {**prev_result, "vulnerabilities": vulns}
    except Exception as e:
        logger.exception("Error in nuclei_task")
        run_async(update_scan_status(UUID(scan_id), "failed", datetime.utcnow()))
        raise e

# Chain entrypoint
@celery_app.task
def start_scan_chain(scan_id: str, target: str, nuclei_templates):
    return chain(
        subfinder_task.s(scan_id, target),
        katana_task.s(scan_id, target),
        naabu_task.s(scan_id, target),
        nuclei_task.s(scan_id, target, nuclei_templates)
    )() 