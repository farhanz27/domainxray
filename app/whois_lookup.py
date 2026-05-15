from __future__ import annotations

import re
import socket
from app.models import WhoisResult

WHOIS_SERVERS: dict[str, str] = {
    # Generic TLDs
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.pir.org",
    "info": "whois.afilias.net",
    "biz": "whois.biz",
    "name": "whois.nic.name",
    "mobi": "whois.dotmobiregistry.net",
    "pro": "whois.registrypro.pro",
    # New gTLDs
    "xyz": "whois.nic.xyz",
    "online": "whois.nic.online",
    "site": "whois.nic.site",
    "tech": "whois.nic.tech",
    "cloud": "whois.nic.cloud",
    "store": "whois.nic.store",
    "shop": "whois.nic.shop",
    "app": "whois.nic.google",
    "dev": "whois.nic.google",
    "page": "whois.nic.google",
    "blog": "whois.nic.blog",
    "live": "whois.nic.live",
    "club": "whois.nic.club",
    "fun": "whois.nic.fun",
    "space": "whois.nic.space",
    "icu": "whois.nic.icu",
    "top": "whois.nic.top",
    "vip": "whois.nic.vip",
    "work": "whois.nic.work",
    "ltd": "whois.nic.ltd",
    "group": "whois.nic.group",
    # Country-code TLDs
    "ac": "whois.nic.ac",
    "ai": "whois.nic.ai",
    "au": "whois.auda.org.au",
    "be": "whois.dns.be",
    "br": "whois.registro.br",
    "ca": "whois.cira.ca",
    "ch": "whois.nic.ch",
    "cl": "whois.nic.cl",
    "cn": "whois.cnnic.cn",
    "co": "whois.nic.co",
    "cz": "whois.nic.cz",
    "de": "whois.denic.de",
    "dk": "whois.dk-hostmaster.dk",
    "ee": "whois.tld.ee",
    "eu": "whois.eu",
    "fi": "whois.fi",
    "fr": "whois.nic.fr",
    "gg": "whois.gg",
    "hk": "whois.hkirc.hk",
    "id": "whois.id",
    "ie": "whois.weare.ie",
    "il": "whois.isoc.org.il",
    "in": "whois.registry.in",
    "io": "whois.nic.io",
    "is": "whois.isnic.is",
    "it": "whois.nic.it",
    "jp": "whois.jprs.jp",
    "kr": "whois.kr",
    "li": "whois.nic.li",
    "lt": "whois.domreg.lt",
    "lu": "whois.dns.lu",
    "lv": "whois.nic.lv",
    "me": "whois.nic.me",
    "mx": "whois.mx",
    "my": "whois.mynic.my",
    "nl": "whois.sidn.nl",
    "no": "whois.norid.no",
    "nz": "whois.srs.net.nz",
    "pe": "kero.yachay.pe",
    "ph": "whois.dot.ph",
    "pl": "whois.dns.pl",
    "pt": "whois.dns.pt",
    "ro": "whois.rotld.ro",
    "ru": "whois.tcinet.ru",
    "se": "whois.iis.se",
    "sg": "whois.sgnic.sg",
    "th": "whois.thnic.co.th",
    "tk": "whois.dot.tk",
    "tr": "whois.trabis.gov.tr",
    "tv": "whois.nic.tv",
    "tw": "whois.twnic.net.tw",
    "ua": "whois.ua",
    "uk": "whois.nic.uk",
    "us": "whois.nic.us",
    "za": "whois.registry.net.za",
}

_REFERRAL_PATTERNS = [
    re.compile(r"Registrar WHOIS Server:\s*(.+)", re.IGNORECASE),
    re.compile(r"whois server:\s*(.+)", re.IGNORECASE),
    re.compile(r"refer:\s*(.+)", re.IGNORECASE),
]


def _extract_tld(domain: str) -> str:
    parts = domain.rstrip(".").split(".")
    return parts[-1].lower() if parts else ""


def _raw_whois_query(server: str, domain: str, timeout: float = 10.0) -> str:
    with socket.create_connection((server, 43), timeout=timeout) as sock:
        sock.sendall(f"{domain}\r\n".encode())
        chunks: list[bytes] = []
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
    return b"".join(chunks).decode("utf-8", errors="replace")


def _find_referral(raw: str) -> str | None:
    for pattern in _REFERRAL_PATTERNS:
        m = pattern.search(raw)
        if m:
            server = m.group(1).strip().lower()
            if server and "." in server:
                return server
    return None


def _first_match(raw: str, *patterns: str) -> str | None:
    for pat in patterns:
        m = re.search(pat, raw, re.IGNORECASE | re.MULTILINE)
        if m:
            return m.group(1).strip()
    return None


def _all_matches(raw: str, *patterns: str) -> list[str]:
    seen: set[str] = set()
    results: list[str] = []
    for pat in patterns:
        for m in re.finditer(pat, raw, re.IGNORECASE | re.MULTILINE):
            val = m.group(1).strip().lower()
            if val and val not in seen:
                seen.add(val)
                results.append(val)
    return results


def _parse_whois(raw: str, domain: str) -> WhoisResult:
    result = WhoisResult(domain=domain, raw=raw)

    result.registrar = _first_match(
        raw,
        r"Registrar:\s*(.+)",
        r"Sponsoring Registrar:\s*(.+)",
        r"registrar:\s*(.+)",
    )

    result.creation_date = _first_match(
        raw,
        r"Creation Date:\s*(.+)",
        r"Created Date:\s*(.+)",
        r"created:\s*(.+)",
        r"Registration Date:\s*(.+)",
    )

    result.expiration_date = _first_match(
        raw,
        r"Expir(?:y|ation) Date:\s*(.+)",
        r"Registry Expiry Date:\s*(.+)",
        r"paid-till:\s*(.+)",
        r"expires:\s*(.+)",
    )

    result.updated_date = _first_match(
        raw,
        r"Updated Date:\s*(.+)",
        r"Last Modified:\s*(.+)",
        r"last-updated:\s*(.+)",
    )

    result.name_servers = _all_matches(
        raw,
        r"Name Server:\s*(.+)",
        r"nserver:\s*(.+)",
        r"nameserver:\s*(.+)",
    )

    result.status = _all_matches(
        raw,
        r"Domain Status:\s*(\S+)",
        r"Status:\s*(\S+)",
        r"state:\s*(.+)",
    )

    result.emails = _all_matches(
        raw,
        r"Registrant Email:\s*(.+)",
        r"Admin Email:\s*(.+)",
        r"Tech Email:\s*(.+)",
        r"(?:e-mail|email):\s*(\S+@\S+)",
    )

    result.dnssec = _first_match(raw, r"DNSSEC:\s*(.+)", r"dnssec:\s*(.+)")

    return result


class WhoisLookup:
    """Query WHOIS data for a domain via raw TCP socket to port 43."""

    def __init__(
        self,
        timeout: float = 10.0,
        follow_referral: bool = True,
        server_overrides: dict[str, str] | None = None,
    ):
        self.timeout = timeout
        self.follow_referral = follow_referral
        self._servers = {**WHOIS_SERVERS, **(server_overrides or {})}

    def _get_whois_server(self, domain: str) -> str | None:
        tld = _extract_tld(domain)
        return self._servers.get(tld)

    def lookup(self, domain: str) -> WhoisResult:
        domain = domain.lower().strip().rstrip(".")
        server = self._get_whois_server(domain)

        if not server:
            return WhoisResult(
                domain=domain,
                error=f"WHOIS lookup not available for '.{_extract_tld(domain)}' domains",
            )

        try:
            raw = _raw_whois_query(server, domain, self.timeout)
        except Exception as exc:
            return WhoisResult(domain=domain, error=f"WHOIS query failed: {exc}")

        if self.follow_referral:
            referral = _find_referral(raw)
            if referral and referral != server:
                try:
                    raw = _raw_whois_query(referral, domain, self.timeout)
                    server = referral
                except Exception:
                    pass  # fall back to original response

        result = _parse_whois(raw, domain)
        result.whois_server = server
        return result
