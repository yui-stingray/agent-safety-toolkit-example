"""Validate sanitized agent-guard report evidence produced by the demo."""

from __future__ import annotations

import argparse
import json
import sys
from importlib import resources
from pathlib import Path
from typing import Any


REPORT_SCHEMA = "agent-guard.report_evidence.v1.schema.json"
FORBIDDEN_FRAGMENTS = (
    "/home/",
    "/Users/",
    "C:\\Users\\",
    "\\\\server\\",
    "snippet",
    "matched_text",
    "raw_regex",
    "sha256",
    "token",
)


def load_schema() -> dict[str, Any]:
    schema = resources.files("agent_guard.schemas").joinpath(REPORT_SCHEMA)
    return json.loads(schema.read_text(encoding="utf-8"))


def load_payload(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("report payload must be a JSON object")
    return payload


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def validate_report(payload: dict[str, Any], schema: dict[str, Any]) -> dict[str, Any]:
    properties = schema.get("properties", {})
    require(isinstance(properties, dict), "schema.properties must be an object")

    require(payload.get("schema_version") == properties["schema_version"]["const"], "schema_version mismatch")
    require(payload.get("scanner") == properties["scanner"]["const"], "scanner mismatch")
    require(payload.get("command") == properties["command"]["const"], "command mismatch")
    require(payload.get("status") in properties["status"]["enum"], "status is not allowed")
    require(isinstance(payload.get("finding_count"), int), "finding_count must be an integer")
    require(isinstance(payload.get("findings"), list), "findings must be an array")

    report = payload.get("report")
    require(isinstance(report, dict), "report must be an object")
    report_schema = properties["report"]["properties"]
    require(report.get("schema_version") == report_schema["schema_version"]["const"], "report schema mismatch")
    require(report.get("format") == "json", "report format must be json")
    require(report.get("sanitized") is True, "report must be sanitized")

    surface_inventory = payload.get("surface_inventory")
    require(isinstance(surface_inventory, dict), "surface_inventory must be an object")
    surface_schema = properties["surface_inventory"]["properties"]["schema_version"]
    require(surface_inventory.get("schema_version") in surface_schema["enum"], "surface inventory schema mismatch")
    surfaces = surface_inventory.get("surfaces")
    require(isinstance(surfaces, list), "surface_inventory.surfaces must be an array")

    evidence_coverage = payload.get("evidence_coverage")
    require(isinstance(evidence_coverage, dict), "evidence_coverage must be an object")
    require(
        evidence_coverage.get("schema_version") == "agent-guard.evidence_coverage.v1",
        "evidence coverage schema mismatch",
    )
    gates = evidence_coverage.get("gates")
    require(isinstance(gates, list), "evidence_coverage.gates must be an array")

    conformance = payload.get("conformance")
    require(isinstance(conformance, dict), "conformance must be present")
    require(conformance.get("schema_version") == "agent-guard.conformance.v1", "conformance schema mismatch")
    require(conformance.get("profile") == "recommended", "conformance profile mismatch")
    require(conformance.get("status") == "ok", "conformance must pass")

    manifest = payload.get("evidence_pack_manifest")
    require(isinstance(manifest, dict), "evidence_pack_manifest must be present")
    require(
        manifest.get("schema_version") == "agent-guard.evidence_pack_manifest.v1",
        "evidence pack manifest schema mismatch",
    )
    require(manifest.get("sanitized") is True, "evidence pack manifest must be sanitized")

    serialized = json.dumps(payload, sort_keys=True)
    for fragment in FORBIDDEN_FRAGMENTS:
        require(fragment not in serialized, f"forbidden evidence fragment found: {fragment}")

    return {
        "schema_version": payload["schema_version"],
        "status": payload["status"],
        "finding_count": payload["finding_count"],
        "surface_count": len(surfaces),
        "enabled_gate_count": evidence_coverage.get("enabled_count", 0),
        "conformance_status": conformance["status"],
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate a sanitized agent-guard report JSON file.")
    parser.add_argument("report", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        summary = validate_report(load_payload(args.report), load_schema())
    except Exception as exc:
        print(f"agent-guard evidence invalid: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
