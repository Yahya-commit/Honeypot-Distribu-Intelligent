"""Extraction IOC depuis les logs texte Dionaea."""

from __future__ import annotations

import re
from typing import Any

IP_PORT_RE = re.compile(
    r"(?:connection|accept connection) from "
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}):(?P<port>\d+)",
    re.I,
)
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b", re.I)


def _ioc(
    ioc_type: str,
    value: str,
    source: str,
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "type": ioc_type,
        "value": value,
        "source": source,
        "context": context or {},
    }


def parse_dionaea_line(line: str) -> list[dict[str, Any]]:
    iocs: list[dict[str, Any]] = []
    if not line or not line.strip():
        return iocs

    base_ctx = {"honeypot": "dionaea", "raw": line[:500]}

    m = IP_PORT_RE.search(line)
    if m:
        iocs.append(
            _ioc(
                "ipv4",
                m.group("ip"),
                "dionaea",
                {**base_ctx, "src_port": m.group("port"), "role": "attacker"},
            )
        )

    for url in URL_RE.findall(line):
        iocs.append(_ioc("url", url, "dionaea", base_ctx))

    for sha in SHA256_RE.findall(line):
        iocs.append(_ioc("sha256", sha.lower(), "dionaea", base_ctx))

    if "mssql" in line.lower() or "sip" in line.lower() or "smb" in line.lower():
        proto = "unknown"
        for p in ("mssql", "sip", "smb", "ftp", "mqtt", "mysql"):
            if p in line.lower():
                proto = p
                break
        if m:
            iocs.append(_ioc("protocol_probe", proto, "dionaea", base_ctx))

    return iocs
