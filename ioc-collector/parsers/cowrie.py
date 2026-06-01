"""Extraction IOC depuis les événements JSON Cowrie."""

from __future__ import annotations

import hashlib
import re
from typing import Any

URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")


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


def parse_cowrie_line(event: dict[str, Any]) -> list[dict[str, Any]]:
    """Transforme un événement Cowrie en liste d'IOC."""
    iocs: list[dict[str, Any]] = []
    event_id = event.get("eventid", "unknown")
    src_ip = event.get("src_ip") or event.get("peerIP")
    session = event.get("session")
    timestamp = event.get("timestamp")

    base_ctx = {
        "eventid": event_id,
        "session": session,
        "timestamp": timestamp,
        "honeypot": "cowrie",
    }

    if src_ip:
        iocs.append(_ioc("ipv4", src_ip, "cowrie", {**base_ctx, "role": "attacker"}))

    username = event.get("username")
    password = event.get("password")
    if username:
        iocs.append(
            _ioc("username", username, "cowrie", {**base_ctx, "credential_type": "username"})
        )
    if password:
        iocs.append(
            _ioc("password", password, "cowrie", {**base_ctx, "credential_type": "password"})
        )

    command = event.get("input") or event.get("command")
    if command:
        iocs.append(_ioc("command", command[:2000], "cowrie", base_ctx))
        for url in URL_RE.findall(command):
            iocs.append(_ioc("url", url, "cowrie", {**base_ctx, "extracted_from": "command"}))
        for ip in IP_RE.findall(command):
            if ip != src_ip:
                iocs.append(_ioc("ipv4", ip, "cowrie", {**base_ctx, "extracted_from": "command"}))

    url = event.get("url")
    if url:
        iocs.append(_ioc("url", url, "cowrie", base_ctx))

    shasum = event.get("shasum") or event.get("sha256")
    if shasum:
        iocs.append(_ioc("sha256", shasum.lower(), "cowrie", base_ctx))

    for field in ("msg", "format"):
        text = event.get(field)
        if isinstance(text, str):
            for match in SHA256_RE.findall(text):
                iocs.append(_ioc("sha256", match.lower(), "cowrie", base_ctx))
            for match in MD5_RE.findall(text):
                iocs.append(_ioc("md5", match.lower(), "cowrie", base_ctx))

    return iocs


def file_hash(path: str) -> str | None:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None
