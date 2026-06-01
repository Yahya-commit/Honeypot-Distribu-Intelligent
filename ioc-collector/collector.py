#!/usr/bin/env python3
"""
Collecteur IOC — agrège les indicateurs depuis Cowrie et Dionaea.
Sorties : iocs.json, iocs.csv, stats.json
"""

from __future__ import annotations

import csv
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import orjson

from parsers import parse_cowrie_line, parse_dionaea_line
from parsers.cowrie import file_hash

COWRIE_LOG_DIR = Path(os.getenv("COWRIE_LOG_DIR", "/logs/cowrie"))
DIONAEA_LOG_DIR = Path(os.getenv("DIONAEA_LOG_DIR", "/logs/dionaea"))
DOWNLOADS_DIR = Path(os.getenv("DOWNLOADS_DIR", "/downloads/cowrie"))
OUTPUT_DIR = Path(os.getenv("IOC_OUTPUT_DIR", "/data/ioc"))
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL_SEC", "30"))

STATE_FILE = OUTPUT_DIR / ".collector_state.json"
IOCS_JSON = OUTPUT_DIR / "iocs.json"
IOCS_CSV = OUTPUT_DIR / "iocs.csv"
STATS_JSON = OUTPUT_DIR / "stats.json"


def load_state() -> dict[str, Any]:
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            pass
    return {"files": {}, "seen_iocs": []}


def save_state(state: dict[str, Any]) -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2), encoding="utf-8")


def ioc_key(ioc: dict[str, Any]) -> str:
    return f"{ioc['type']}:{ioc['value']}:{ioc['source']}"


def tail_file(path: Path, offset: int) -> tuple[list[str], int]:
    if not path.exists():
        return [], offset
    lines: list[str] = []
    with path.open("r", encoding="utf-8", errors="replace") as f:
        f.seek(offset)
        for line in f:
            lines.append(line.rstrip("\n"))
        new_offset = f.tell()
    return lines, new_offset


def process_cowrie(state: dict[str, Any]) -> list[dict[str, Any]]:
    new_iocs: list[dict[str, Any]] = []
    for log_file in sorted(COWRIE_LOG_DIR.glob("cowrie.json*")):
        key = str(log_file)
        offset = state["files"].get(key, 0)
        lines, new_offset = tail_file(log_file, offset)
        state["files"][key] = new_offset

        for line in lines:
            if not line.strip():
                continue
            try:
                event = orjson.loads(line)
            except orjson.JSONDecodeError:
                continue
            new_iocs.extend(parse_cowrie_line(event))

    if DOWNLOADS_DIR.exists():
        for downloaded in DOWNLOADS_DIR.rglob("*"):
            if not downloaded.is_file():
                continue
            key = f"dl:{downloaded}"
            if key in state["files"]:
                continue
            sha = file_hash(str(downloaded))
            if sha:
                new_iocs.append(
                    {
                        "type": "sha256",
                        "value": sha,
                        "source": "cowrie_download",
                        "context": {
                            "honeypot": "cowrie",
                            "filename": downloaded.name,
                            "path": str(downloaded),
                        },
                    }
                )
            state["files"][key] = 1

    return new_iocs


def process_dionaea(state: dict[str, Any]) -> list[dict[str, Any]]:
    new_iocs: list[dict[str, Any]] = []
    if not DIONAEA_LOG_DIR.exists():
        return new_iocs

    for log_file in sorted(DIONAEA_LOG_DIR.rglob("*.log")):
        key = str(log_file)
        offset = state["files"].get(key, 0)
        lines, new_offset = tail_file(log_file, offset)
        state["files"][key] = new_offset
        for line in lines:
            new_iocs.extend(parse_dionaea_line(line))

    return new_iocs


def merge_iocs(
    existing: list[dict[str, Any]], new: list[dict[str, Any]], seen: set[str]
) -> list[dict[str, Any]]:
    merged = list(existing)
    now = datetime.now(timezone.utc).isoformat()

    for ioc in new:
        key = ioc_key(ioc)
        if key in seen:
            continue
        seen.add(key)
        ioc["first_seen"] = now
        ioc["last_seen"] = now
        merged.append(ioc)

    return merged


def update_timestamps(existing: list[dict[str, Any]], seen_keys: set[str]) -> None:
    now = datetime.now(timezone.utc).isoformat()
    for ioc in existing:
        if ioc_key(ioc) in seen_keys:
            ioc["last_seen"] = now


def compute_stats(iocs: list[dict[str, Any]]) -> dict[str, Any]:
    by_type: dict[str, int] = {}
    by_source: dict[str, int] = {}
    unique_ips: set[str] = set()

    for ioc in iocs:
        by_type[ioc["type"]] = by_type.get(ioc["type"], 0) + 1
        by_source[ioc["source"]] = by_source.get(ioc["source"], 0) + 1
        if ioc["type"] == "ipv4":
            unique_ips.add(ioc["value"])

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_iocs": len(iocs),
        "unique_attacker_ips": len(unique_ips),
        "by_type": by_type,
        "by_source": by_source,
        "top_attackers": sorted(unique_ips)[:50],
    }


def export_csv(iocs: list[dict[str, Any]]) -> None:
    fields = ["type", "value", "source", "first_seen", "last_seen", "context"]
    with IOCS_CSV.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for ioc in iocs:
            row = dict(ioc)
            row["context"] = json.dumps(ioc.get("context", {}), ensure_ascii=False)
            writer.writerow(row)


def export_json(iocs: list[dict[str, Any]], stats: dict[str, Any]) -> None:
    payload = {
        "meta": {
            "project": "Honeypot Distribué Intelligent",
            "version": "1.0",
            "updated_at": stats["generated_at"],
        },
        "stats": stats,
        "iocs": iocs,
    }
    IOCS_JSON.write_bytes(orjson.dumps(payload, option=orjson.OPT_INDENT_2))


def run_once(state: dict[str, Any]) -> None:
    seen = set(state.get("seen_iocs", []))
    existing: list[dict[str, Any]] = []
    if IOCS_JSON.exists():
        try:
            data = json.loads(IOCS_JSON.read_text(encoding="utf-8"))
            existing = data.get("iocs", [])
            seen = {ioc_key(i) for i in existing}
        except json.JSONDecodeError:
            pass

    new_batch: list[dict[str, Any]] = []
    new_batch.extend(process_cowrie(state))
    new_batch.extend(process_dionaea(state))

    merged = merge_iocs(existing, new_batch, seen)
    state["seen_iocs"] = list(seen)

    stats = compute_stats(merged)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    export_json(merged, stats)
    export_csv(merged)
    STATS_JSON.write_text(json.dumps(stats, indent=2), encoding="utf-8")

    print(
        f"[{stats['generated_at']}] IOC total={stats['total_iocs']} "
        f"IPs uniques={stats['unique_attacker_ips']} "
        f"(+{len(new_batch)} nouveaux bruts)"
    )


def main() -> None:
    print("Démarrage collecteur IOC…")
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    state = load_state()

    while True:
        try:
            run_once(state)
            save_state(state)
        except Exception as exc:  # noqa: BLE001 — boucle de service
            print(f"Erreur collecteur: {exc}")
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
