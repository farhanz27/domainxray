from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class DNSRecord:
    record_type: str
    name: str
    value: str
    ttl: int = 0
    priority: Optional[int] = None  # MX / SRV

    def to_dict(self) -> dict:
        d = asdict(self)
        if d["priority"] is None:
            del d["priority"]
        return d


@dataclass
class DNSResult:
    domain: str
    records: dict[str, list[DNSRecord]] = field(default_factory=dict)
    resolver: str = ""
    error: Optional[str] = None
    errors: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        d: dict = {
            "domain": self.domain,
            "resolver": self.resolver,
            "records": {
                rtype: [r.to_dict() for r in recs]
                for rtype, recs in self.records.items()
            },
            "errors": self.errors,
        }
        if self.error:
            d["error"] = self.error
        return d


@dataclass
class WhoisResult:
    domain: str
    registrar: Optional[str] = None
    creation_date: Optional[str] = None
    expiration_date: Optional[str] = None
    updated_date: Optional[str] = None
    name_servers: list[str] = field(default_factory=list)
    status: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    dnssec: Optional[str] = None
    whois_server: Optional[str] = None
    raw: str = ""
    error: Optional[str] = None

    def to_dict(self) -> dict:
        d = asdict(self)
        del d["raw"]
        if d["error"] is None:
            del d["error"]
        return d


@dataclass
class DomainReport:
    domain: str
    dns: Optional[DNSResult] = None
    whois: Optional[WhoisResult] = None

    def to_dict(self) -> dict:
        result: dict = {"domain": self.domain}
        if self.dns:
            result["dns"] = self.dns.to_dict()
        if self.whois:
            result["whois"] = self.whois.to_dict()
        return result

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)
