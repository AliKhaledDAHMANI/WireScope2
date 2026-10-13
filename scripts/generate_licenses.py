#!/usr/bin/env python3
"""Emit installed Python distribution license metadata for release review."""
from __future__ import annotations

import argparse
import json
from importlib import metadata
from pathlib import Path


def license_of(dist: metadata.Distribution) -> str:
    try:
        meta = dist.metadata
        expression = meta.get("License-Expression")
        if expression:
            return expression
        license_text = (meta.get("License") or "").strip()
        if license_text and license_text.lower() not in {"unknown", "see license"}:
            return license_text[:300]
        classifiers = [c.rsplit("::", 1)[-1] for c in meta.get_all("Classifier", []) if c.startswith("License :: OSI Approved ::")]
        return "; ".join(classifiers) or "REVIEW REQUIRED: no license metadata"
    except Exception:
        return "REVIEW REQUIRED: metadata unavailable"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("THIRD_PARTY_LICENSES.json"))
    args = parser.parse_args()
    records = []
    for dist in metadata.distributions():
        name = dist.metadata.get("Name")
        version = dist.version
        if not name:
            continue
        records.append({"name": name, "version": version, "license": license_of(dist)})
    records.sort(key=lambda item: item["name"].casefold())
    args.output.write_text(json.dumps({"generated_by": "scripts/generate_licenses.py", "distributions": records}, indent=2) + "\n", encoding="utf-8")
    needs_review = [entry for entry in records if entry["license"].startswith("REVIEW REQUIRED")]
    print(f"Wrote {len(records)} installed distribution records to {args.output}")
    if needs_review:
        print(f"Review {len(needs_review)} entries with missing license metadata before publishing a bundled release.")


if __name__ == "__main__":
    main()
