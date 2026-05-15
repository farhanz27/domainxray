"""Thin FastAPI layer over DomainXray."""

from __future__ import annotations

import ipaddress
import socket
import ssl as _ssl
import datetime as _dt
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app.inspector import DomainXray

DEFAULT_PUBLIC_DNS = "8.8.8.8"

api = FastAPI(title="DomainXray — DNS & WHOIS Analysis API")

api.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def _normalize_resolver(resolver: str | None) -> str:
    """Return a validated resolver IP; empty input uses DEFAULT_PUBLIC_DNS."""
    raw = (resolver or "").strip()
    if not raw:
        return DEFAULT_PUBLIC_DNS
    if raw.startswith("[") and raw.endswith("]"):
        raw = raw[1:-1]
    try:
        ipaddress.ip_address(raw)
    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail=(
                f"Invalid DNS resolver {resolver!r}. "
                "Use an IPv4 address (e.g. 8.8.8.8) or IPv6 (e.g. 2606:4700:4700::1111)."
            ),
        ) from exc
    return raw


def _xray_dns(resolver: str | None) -> DomainXray:
    addr = _normalize_resolver(resolver)
    return DomainXray(nameservers=[addr])


@api.get("/api/inspect")
def inspect(
    domain: str = Query(..., min_length=1),
    resolver: str | None = Query(
        None,
        description=f"DNS resolver IPv4/IPv6; omit for {DEFAULT_PUBLIC_DNS}",
    ),
):
    return _xray_dns(resolver).inspect(domain).to_dict()


@api.get("/api/dns")
def dns(
    domain: str = Query(..., min_length=1),
    types: str | None = Query(None, description="Comma-separated record types"),
    resolver: str | None = Query(
        None,
        description=f"DNS resolver IPv4/IPv6; omit for {DEFAULT_PUBLIC_DNS}",
    ),
):
    record_types = [t.strip().upper() for t in types.split(",")] if types else None
    return _xray_dns(resolver).dns_only(domain, record_types).to_dict()


@api.get("/api/whois")
def whois(domain: str = Query(..., min_length=1)):
    return DomainXray().whois_only(domain).to_dict()


@api.get("/api/ssl")
def ssl_check(domain: str = Query(..., min_length=1)):
    try:
        ctx = _ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))
        fmt = "%b %d %H:%M:%S %Y %Z"
        expiry = _dt.datetime.strptime(cert.get("notAfter", ""), fmt)
        issued = _dt.datetime.strptime(cert.get("notBefore", ""), fmt)
        days_left = (expiry - _dt.datetime.utcnow()).days
        sans = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]
        return {
            "domain": domain,
            "common_name": subject.get("commonName", ""),
            "issuer": issuer.get("organizationName") or issuer.get("commonName", ""),
            "issued": issued.strftime("%Y-%m-%d"),
            "expires": expiry.strftime("%Y-%m-%d"),
            "days_until_expiry": days_left,
            "san": sans[:10],
            "valid": days_left > 0,
        }
    except _ssl.SSLCertVerificationError:
        return {"domain": domain, "error": "Certificate verification failed"}
    except ConnectionRefusedError:
        return {"domain": domain, "error": "Port 443 refused"}
    except socket.timeout:
        return {"domain": domain, "error": "Connection timed out"}
    except socket.gaierror:
        return {"domain": domain, "error": "DNS resolution failed"}
    except Exception as exc:
        return {"domain": domain, "error": str(exc)[:120]}


@api.get("/api/bulk")
def bulk_scan(
    domains: str = Query(..., description="Comma-separated list of domains"),
    resolver: str | None = Query(None),
    mode: str = Query("full", description="full, dns, or whois"),
):
    domain_list = [d.strip() for d in domains.split(",") if d.strip()]
    if not domain_list:
        raise HTTPException(422, "No valid domains provided")
    if len(domain_list) > 20:
        raise HTTPException(422, "Maximum 20 domains per bulk request")
    addr = _normalize_resolver(resolver)

    def scan(d: str) -> dict:
        try:
            xray = DomainXray(nameservers=[addr])
            if mode == "dns":
                return xray.dns_only(d).to_dict()
            if mode == "whois":
                return DomainXray().whois_only(d).to_dict()
            return xray.inspect(d).to_dict()
        except Exception as exc:
            return {"domain": d, "error": str(exc)}

    with ThreadPoolExecutor(max_workers=min(len(domain_list), 5)) as pool:
        results = list(pool.map(scan, domain_list))
    return results


_dist = Path(__file__).parent / "frontend" / "dist"
if _dist.is_dir():
    api.mount("/", StaticFiles(directory=_dist, html=True), name="static")
