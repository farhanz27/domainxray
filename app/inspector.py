from __future__ import annotations

from app.dns_lookup import DNSLookup
from app.whois_lookup import WhoisLookup
from app.models import DNSResult, WhoisResult, DomainReport


class DomainXray:
    """Unified interface for DNS + WHOIS domain intelligence."""

    def __init__(
        self,
        nameservers: list[str] | None = None,
        dns_timeout: float = 5.0,
        whois_timeout: float = 10.0,
        follow_referral: bool = True,
    ):
        self.dns = DNSLookup(
            nameservers=nameservers,
            timeout=dns_timeout,
        )
        self.whois = WhoisLookup(
            timeout=whois_timeout,
            follow_referral=follow_referral,
        )

    def inspect(self, domain: str) -> DomainReport:
        """Full inspection: DNS + WHOIS."""
        dns_result = self.dns.resolve_all(domain)
        whois_result = self.whois.lookup(domain)
        return DomainReport(domain=domain, dns=dns_result, whois=whois_result)

    def dns_only(self, domain: str, record_types: list[str] | None = None) -> DNSResult:
        return self.dns.resolve_all(domain, record_types)

    def whois_only(self, domain: str) -> WhoisResult:
        return self.whois.lookup(domain)
