from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

WEIGHTS = {"process": 40, "domain": 40, "shutdown": 25, "unknown_network": 20,
           "profile": 10, "crash": 10}
SUPPORTED = {".json", ".csv", ".txt", ".log"}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def parse_time(value: Any) -> str | None:
    if not value:
        return None
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(value, timezone.utc).isoformat()
        except (OverflowError, OSError, ValueError):
            return None
    text = str(value).strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).isoformat()
    except ValueError:
        return text


def first(record: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if record.get(key) not in (None, ""):
            return record[key]
    return None


def flatten_json(obj: Any):
    if isinstance(obj, list):
        for item in obj:
            yield from flatten_json(item)
    elif isinstance(obj, dict):
        # MVT modules generally serialize an array of objects. Preserve nested
        # evidence records while avoiding metadata-only wrapper objects.
        children = [v for v in obj.values() if isinstance(v, (dict, list))]
        if children and not any(k in obj for k in ("process", "process_name", "domain", "url", "path", "timestamp", "time", "signal_type", "type")):
            for value in children:
                yield from flatten_json(value)
        else:
            yield obj


def infer_signal(row: dict[str, Any], filename: str) -> tuple[str | None, Any]:
    signal = str(first(row, "signal_type", "category", "entity_type") or "").lower().replace("-", "_")
    aliases = {"process_name": "process", "malicious_process": "process", "one_time_domain": "domain",
               "url": "domain", "sticky_process": "shutdown", "shutdown_log": "shutdown",
               "network": "unknown_network", "network_egress": "unknown_network",
               "configuration_profile": "profile", "profile_event": "profile", "crash_ref": "crash"}
    signal = aliases.get(signal, signal)
    value = first(row, "value", "indicator", "process_name", "process", "binary", "domain", "url", "path", "profile", "name")
    lower = filename.lower()
    if signal in WEIGHTS:
        return signal, value
    if "shutdown" in lower:
        return "shutdown", value or row.get("raw")
    if "netusage" in lower or "process" in lower:
        return "process", value
    if any(x in lower for x in ("url", "cache", "safari", "domain", "webkit")):
        return "domain", value
    return None, value


def parse_shutdown_text(text: str):
    # A conservative generic extractor: only lines containing a process path
    # are emitted. No device-specific proprietary parser is claimed here.
    for line in text.splitlines():
        if "/" not in line or not re.search(r"(?:client|process|pid|sticky|shutdown)", line, re.I):
            continue
        timestamp = None
        match = re.search(r"\b(20\d\d[-/]\d\d[-/]\d\d[ T]\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)?)", line)
        if match:
            timestamp = match.group(1)
        path = re.search(r"(/[^\s,;\]\[()]+)", line)
        if path:
            yield {"signal_type": "shutdown", "value": path.group(1), "timestamp": timestamp,
                   "detail": line.strip(), "sticky": True}


def read_records(evidence_dir: Path):
    records: list[dict[str, Any]] = []
    files = sorted(p for p in evidence_dir.rglob("*") if p.is_file() and p.suffix.lower() in SUPPORTED)
    if not files:
        raise ValueError(f"No supported evidence files found in {evidence_dir}")
    hashes = []
    for path in files:
        rel = path.relative_to(evidence_dir).as_posix()
        hashes.append({"path": rel, "sha256": sha256_file(path), "bytes": path.stat().st_size})
        suffix = path.suffix.lower()
        try:
            if suffix == ".csv":
                with path.open(encoding="utf-8-sig", newline="") as f:
                    source_rows = list(csv.DictReader(f))
            elif suffix == ".json":
                source_rows = list(flatten_json(json.loads(path.read_text(encoding="utf-8"))))
            else:
                text = path.read_text(encoding="utf-8", errors="replace")
                source_rows = list(parse_shutdown_text(text)) if "shutdown" in path.name.lower() else []
            for raw in source_rows:
                signal, value = infer_signal(raw, path.name)
                if not signal or value in (None, ""):
                    continue
                records.append({"source": rel, "signal_type": signal, "value": str(value),
                                "timestamp": parse_time(first(raw, "timestamp", "time", "date", "event_time")),
                                "detail": str(first(raw, "detail", "description", "raw") or ""),
                                "sticky": bool(raw.get("sticky", False)), "raw": raw})
        except (OSError, UnicodeError, json.JSONDecodeError, csv.Error) as exc:
            raise ValueError(f"Could not parse {rel}: {exc}") from exc
    return records, hashes


def load_iocs(path: Path | None):
    if path is None:
        return {"process": [], "domain": [], "path": []}
    data = json.loads(path.read_text(encoding="utf-8"))
    result: dict[str, list[dict[str, str]]] = {"process": [], "domain": [], "path": []}
    if isinstance(data, dict) and data.get("type") == "bundle":
        objects = data.get("objects", [])
        for obj in objects:
            if obj.get("type") != "indicator":
                continue
            pattern = obj.get("pattern", "")
            for field, raw in re.findall(r"(process:name|domain-name:value|file:name|file:path)\s*=\s*'((?:\\.|[^'])*)'", pattern, re.I):
                category = "process" if field.lower().startswith("process") else "domain" if field.lower().startswith("domain") else "path"
                result[category].append({"value": raw.replace("\\'", "'"), "name": obj.get("name", "STIX indicator")})
    else:
        for category in result:
            values = data.get(category, []) if isinstance(data, dict) else []
            for entry in values:
                if isinstance(entry, str):
                    result[category].append({"value": entry, "name": entry})
                elif isinstance(entry, dict) and entry.get("value"):
                    result[category].append({"value": str(entry["value"]), "name": str(entry.get("name", entry["value"]))})
    return result


def verify_manifest(evidence_dir: Path, manifest: Path | None):
    if manifest is None:
        return
    with manifest.open(encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))
    for row in rows:
        rel, expected = row.get("path"), (row.get("sha256") or "").lower()
        file_path = (evidence_dir / str(rel)).resolve()
        if not rel or not expected or evidence_dir.resolve() not in file_path.parents or not file_path.is_file():
            raise ValueError(f"Invalid manifest entry: {row}")
        actual = sha256_file(file_path)
        if actual != expected:
            raise ValueError(f"Integrity check failed for {rel}: expected {expected}, got {actual}")


def correlate(records, iocs, window_seconds):
    hits = []
    for rec in records:
        kind, val = rec["signal_type"], rec["value"]
        category = "path" if kind == "shutdown" else kind
        match = next((ioc for ioc in iocs.get(category, []) if ioc["value"].lower() in val.lower()), None)
        weight = 0
        reason = ""
        if match and kind in ("process", "domain", "shutdown"):
            weight = WEIGHTS["process" if kind == "process" else "domain" if kind == "domain" else "shutdown"]
            reason = f"Matched IOC: {match['name']}"
        elif kind == "shutdown" and (rec["sticky"] or any(s in val.lower() for s in ("/private/var/db/", "pegasus", "predator", "reign"))):
            weight, reason = WEIGHTS["shutdown"], "Shutdown-log path requires review; generic heuristic"
        elif kind == "unknown_network":
            weight, reason = WEIGHTS["unknown_network"], "Input explicitly labels unknown-binary network egress"
        elif kind in ("profile", "crash"):
            weight, reason = WEIGHTS[kind], f"Low-specificity {kind} context"
        rec.update({"weight": weight, "reason": reason})
        if weight:
            hits.append(rec)
    cluster = False
    timed = [h for h in hits if h["timestamp"]]
    timed.sort(key=lambda x: x["timestamp"])
    for i, left in enumerate(timed):
        try:
            t0 = datetime.fromisoformat(left["timestamp"])
            for right in timed[i + 1:]:
                t1 = datetime.fromisoformat(right["timestamp"])
                if (t1 - t0).total_seconds() > window_seconds:
                    break
                if left["signal_type"] != right["signal_type"]:
                    cluster = True
                    break
        except ValueError:
            continue
        if cluster:
            break
    raw_score = sum(h["weight"] for h in hits)
    score = round(raw_score * (1.5 if cluster else 1), 1)
    verdict = "High" if score >= 60 else "Medium" if score >= 30 else "Low"
    return hits, score, verdict, cluster


def write_outputs(out: Path, evidence_dir: Path, records, hashes, score, verdict, cluster, window_seconds):
    out.mkdir(parents=True, exist_ok=True)
    timeline = sorted(records, key=lambda r: r["timestamp"] or "")
    evidence_log = [{k: h.get(k) for k in ("source", "timestamp", "signal_type", "value", "weight", "reason", "detail")} for h in records if h["weight"]]
    result = {"tool": "PEG-TRIAGE", "version": "1.0.0", "generated_utc": datetime.now(timezone.utc).isoformat(),
              "evidence_directory": evidence_dir.name, "score": score, "verdict": verdict,
              "temporal_cluster": cluster, "cluster_window_seconds": window_seconds,
              "interpretation": "Triage aid only. Low means no corroborated indicators in supplied artifacts; it does not establish a clean device.",
              "input_hashes": hashes, "timeline": [{k: r.get(k) for k in ("timestamp", "source", "signal_type", "value", "weight", "reason", "detail")} for r in timeline],
              "evidence_log": evidence_log}
    (out / "report.json").write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    fields = ("timestamp", "source", "signal_type", "value", "weight", "reason", "detail")
    with (out / "timeline.csv").open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows({key: r.get(key, "") for key in fields} for r in timeline)
    rows = "\n".join(f"| {e['timestamp'] or 'Unknown'} | {e['signal_type']} | `{e['value']}` | {e['weight']} | {e['source']} | {e['reason']} |" for e in evidence_log) or "| - | - | - | 0 | - | No scored indicators |"
    md = f"""# PEG-TRIAGE Analysis Report\n\n- **Generated (UTC):** {result['generated_utc']}\n- **Score:** {score}\n- **Triage verdict:** {verdict}\n- **Temporal cluster:** {'yes' if cluster else 'no'} (window {window_seconds}s)\n- **Evidence files hashed:** {len(hashes)}\n\n> {result['interpretation']}\n\n## Scored evidence\n\n| Timestamp | Signal | Value | Points | Source artifact | Reason |\n|---|---|---|---:|---|---|\n{rows}\n\n## Input integrity\n\n| Relative path | SHA-256 | Bytes |\n|---|---|---:|\n""" + "\n".join(f"| `{h['path']}` | `{h['sha256']}` | {h['bytes']} |" for h in hashes) + "\n"
    (out / "report.md").write_text(md, encoding="utf-8")
    return result


def make_demo(out: Path):
    demo = out / "peg-triage-demo"
    demo.mkdir(parents=True, exist_ok=True)
    sample = Path(__file__).resolve().parent.parent / "examples" / "synthetic_case"
    import shutil
    shutil.copytree(sample, demo, dirs_exist_ok=True)
    return demo


def main(argv=None):
    parser = argparse.ArgumentParser(description="Correlate indicators in already-acquired mobile forensic exports.")
    parser.add_argument("--evidence", type=Path, help="Folder with MVT JSON/CSV exports or normalized CSV/log artifacts")
    parser.add_argument("--iocs", type=Path, help="IOC JSON (PEG-TRIAGE format or a STIX 2 bundle subset)")
    parser.add_argument("--manifest", type=Path, help="Optional custody CSV with path,sha256 columns; every listed hash must match")
    parser.add_argument("--out", type=Path, default=Path("peg-triage-results"), help="Output folder (default: ./peg-triage-results)")
    parser.add_argument("--window", type=int, default=120, help="Temporal-correlation window in seconds (default: 120)")
    parser.add_argument("--demo", action="store_true", help="Create and analyze the included synthetic demonstration")
    args = parser.parse_args(argv)
    try:
        evidence = make_demo(args.out) if args.demo else args.evidence
        if evidence is None or not evidence.is_dir():
            parser.error("provide an existing --evidence folder, or use --demo")
        verify_manifest(evidence, args.manifest)
        records, hashes = read_records(evidence)
        iocs = load_iocs(args.iocs)
        hits, score, verdict, cluster = correlate(records, iocs, max(1, args.window))
        result = write_outputs(args.out, evidence, records, hashes, score, verdict, cluster, max(1, args.window))
        print(f"PEG-TRIAGE: {verdict} ({score} points); {len(hits)} scored finding(s)")
        print(f"Report: {(args.out / 'report.md').resolve()}")
        return 0
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
