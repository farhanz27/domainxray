from __future__ import annotations

import dns.resolver
import dns.rdatatype
import dns.name

from app.models import DNSRecord, DNSResult

DEFAULT_RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "PTR", "SRV", "CAA"]


class DNSLookup:
    """Resolve DNS records for a domain using dnspython."""

    def __init__(
        self,
        nameservers: list[str] | None = None,
        timeout: float = 5.0,
        lifetime: float = 10.0,
    ):
        self._resolver = dns.resolver.Resolver()
        if nameservers:
            self._resolver.nameservers = nameservers
        self._resolver.timeout = timeout
        self._resolver.lifetime = lifetime

    @property
    def resolver_address(self) -> str:
        return self._resolver.nameservers[0] if self._resolver.nameservers else "system-default"

    def resolve(self, domain: str, record_type: str) -> list[DNSRecord]:
        rtype = record_type.upper()
        records: list[DNSRecord] = []
        answer = self._resolver.resolve(domain, rtype)

        for rdata in answer:
            rec = DNSRecord(
                record_type=rtype,
                name=str(answer.qname).rstrip("."),
                value=str(rdata).strip('"'),
                ttl=answer.ttl,
            )
            if rtype == "MX":
                rec.priority = rdata.preference  # type: ignore[attr-defined]
            elif rtype == "SRV":
                rec.priority = rdata.priority  # type: ignore[attr-defined]
            records.append(rec)

        return records

    def resolve_all(
        self,
        domain: str,
        record_types: list[str] | None = None,
    ) -> DNSResult:
        types = record_types or DEFAULT_RECORD_TYPES
        result = DNSResult(domain=domain, resolver=self.resolver_address)

        for rtype in types:
            try:
                recs = self.resolve(domain, rtype)
                if recs:
                    result.records[rtype] = recs
            except dns.resolver.NoAnswer:
                pass
            except dns.resolver.NXDOMAIN:
                result.error = f"Domain '{domain}' does not exist"
                break
            except dns.resolver.NoNameservers:
                result.errors[rtype] = "no nameservers available"
            except dns.resolver.Timeout:
                result.errors[rtype] = "query timed out"
            except Exception as exc:
                result.errors[rtype] = str(exc)

        return result
