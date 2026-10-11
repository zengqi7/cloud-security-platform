#!/usr/bin/env python3
import argparse
import hashlib
import io
import json
import pathlib
import tarfile

import yaml


ROOT = pathlib.Path(__file__).resolve().parents[1]
LOCK = json.loads((ROOT / "capacity" / "lock.json").read_text(encoding="utf-8"))


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def workloads(document):
    if document.get("kind") == "List":
        return document.get("items") if isinstance(document.get("items"), list) else []
    return [document]


def pod_spec(resource):
    kind = resource.get("kind")
    spec = resource.get("spec") or {}
    if kind == "Pod":
        return spec
    if kind in {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job"}:
        return ((spec.get("template") or {}).get("spec") or {})
    if kind == "CronJob":
        return (((((spec.get("jobTemplate") or {}).get("spec") or {}).get("template") or {}).get("spec")) or {})
    return None


def classify(resource):
    if not isinstance(resource, dict) or resource.get("kind") not in LOCK["selection"]["supported_kinds"]:
        return "excluded_unsupported_kind"
    metadata = resource.get("metadata") or {}
    spec = pod_spec(resource)
    if not resource.get("apiVersion") or not metadata.get("name") or not isinstance(spec, dict):
        return "excluded_invalid_workload"
    containers = spec.get("containers")
    if not isinstance(containers, list) or not containers:
        return "excluded_invalid_workload"
    all_containers = list(containers)
    all_containers.extend(spec.get("initContainers") or [])
    all_containers.extend(spec.get("ephemeralContainers") or [])
    if any(not isinstance(item, dict) or not item.get("name") or not item.get("image") for item in all_containers):
        return "excluded_invalid_workload"
    return "included"


def main():
    parser = argparse.ArgumentParser(description="Prepare the pinned KALM workload corpus")
    parser.add_argument("archive", type=pathlib.Path)
    parser.add_argument("--output", type=pathlib.Path, default=ROOT / "data" / "capacity")
    args = parser.parse_args()
    archive_bytes = args.archive.read_bytes()
    actual = sha256(archive_bytes)
    expected = LOCK["source"]["archive_sha256"]
    if actual != expected:
        raise SystemExit(f"archive checksum mismatch: expected {expected}, got {actual}")

    records = []
    license_bytes = None
    yaml_files = 0
    documents = 0
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as archive:
        for member in archive.getmembers():
            parts = pathlib.PurePosixPath(member.name).parts
            if member.isfile() and parts[-1] == "LICENSE":
                license_bytes = archive.extractfile(member).read()
            if not member.isfile() or "manifests" not in parts or pathlib.PurePosixPath(member.name).suffix not in {".yaml", ".yml"}:
                continue
            yaml_files += 1
            raw = archive.extractfile(member).read()
            for index, document in enumerate(yaml.safe_load_all(raw), start=1):
                if document is None:
                    continue
                for item_index, resource in enumerate(workloads(document), start=1):
                    documents += 1
                    status = classify(resource)
                    canonical = json.dumps(resource, sort_keys=True, separators=(",", ":")).encode() if isinstance(resource, dict) else b"null"
                    records.append({"source_path": "/".join(parts[1:]), "document_index": index, "item_index": item_index, "status": status, "canonical_sha256": sha256(canonical), "resource": resource if status == "included" else None})

    included = [item for item in records if item["status"] == "included"]
    excluded = [item for item in records if item["status"] != "included"]
    observed = {"yaml_files": yaml_files, "documents": documents, "included": len(included), "excluded": len(excluded)}
    if observed != LOCK["expected"]:
        raise SystemExit(f"selection drift: expected {LOCK['expected']}, got {observed}")
    if license_bytes is None:
        raise SystemExit("upstream LICENSE not found")

    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    corpus_bytes = (json.dumps(included, sort_keys=True, separators=(",", ":")) + "\n").encode()
    audit_bytes = (json.dumps(records, sort_keys=True, separators=(",", ":")) + "\n").encode()
    (output / "corpus.json").write_bytes(corpus_bytes)
    (output / "selection-audit.json").write_bytes(audit_bytes)
    (output / "upstream-LICENSE").write_bytes(license_bytes)
    manifest = {"source_commit": LOCK["source"]["commit"], "source_archive_sha256": actual, **observed, "corpus_sha256": sha256(corpus_bytes), "selection_audit_sha256": sha256(audit_bytes)}
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(output), **manifest}))


if __name__ == "__main__":
    main()
