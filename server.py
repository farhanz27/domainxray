"""Thin FastAPI layer over DomainXray."""

from __future__ import annotations

import ipaddress
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


_dist = Path(__file__).parent / "frontend" / "dist"
if _dist.is_dir():
    api.mount("/", StaticFiles(directory=_dist, html=True), name="static")
