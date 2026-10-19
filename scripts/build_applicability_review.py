"""Produce a hash-bound configuration review queue; never auto-clear a CVE.

An advisory mentioning a Kconfig symbol does not prove that disabling that
symbol excludes the vulnerability. Record observations and require source,
linkage and reachability review instead of guessing necessary conditions.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re


def build_review(rows, assessment, config_text, image_sha256):
    config = {}
    for line in config_text.splitlines():
        match = re.fullmatch(r"(CONFIG_[A-Z0-9_]+)=(.*)", line)
        disabled = re.fullmatch(r"# (CONFIG_[A-Z0-9_]+) is not set", line)
        if match:
            config[match[1]] = match[2]
        elif disabled:
            config[disabled[1]] = "n"
    by_id = {row["ghsa_id"]: row for row in rows}
    queue = []
    for candidate in assessment["results"]:
        if candidate["status"] in {"not_in_reported_range", "fixed", "not_affected"}:
            continue
        row = by_id[candidate["advisory_id"]]
        symbols = sorted(set(re.findall(r"\bCONFIG_[A-Z0-9_]+\b",
                                        str(row.get("description", "")))))
        queue.append({
            "advisory_id": candidate["advisory_id"], "cve_id": candidate.get("cve_id"),
            "version_status": candidate["status"], "source_url": row["html_url"],
            "official_sha256": hashlib.sha256(json.dumps(row, sort_keys=True, ensure_ascii=False).encode()).hexdigest(),
            "configuration_observations": {symbol: config.get(symbol, "not_recorded") for symbol in symbols},
            "required_reviews": ["component_and_package_revision", "necessary_configuration_conditions",
                                 "linked_code_and_patch_provenance", "reachable_trigger_path"],
            "conclusion": "requires_review", "business_accepted": False,
        })
    return {"image_sha256": image_sha256,
            "config_sha256": hashlib.sha256(config_text.encode()).hexdigest(),
            "version": assessment["version"], "open_count": len(queue), "items": queue,
            "configuration_exclusion_is_proven": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--assessment", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    rows = json.loads(args.snapshot.read_text(encoding="utf-8-sig"))
    if isinstance(rows, dict):
        rows = rows["rows"]
    result = build_review(rows, json.loads(args.assessment.read_text(encoding="utf-8-sig")),
                          args.config.read_bytes().decode("utf-8"),
                          hashlib.sha256(args.image.read_bytes()).hexdigest())
    with args.output.open("x", encoding="utf-8") as output:
        json.dump(result, output, ensure_ascii=False, indent=2)
    print(json.dumps({"open_count": result["open_count"], "automatically_excluded": 0}))


if __name__ == "__main__":
    main()
