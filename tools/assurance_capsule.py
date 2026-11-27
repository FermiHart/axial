#!/usr/bin/env python3
"""Offline, unsigned build metadata. Never an authorization check."""
import argparse
import hashlib
import json
import pathlib
import re

EVIDENCE = "build.json"
CAPSULE = "capsule.json"
SOURCES = {"LICENSE", "vendor/ed25519.c", "vendor/ed25519.h", "vendor/sha256_ni.h"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def hex_digest(value, size):
    return isinstance(value, str) and re.fullmatch("[0-9a-f]{%d}" % size, value) is not None


def encode(obj):
    return (json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("ascii")


def expected(report, payload):
    require(isinstance(report, dict) and type(report.get("schema_version")) is int
            and report["schema_version"] == 1, "build schema")
    require(report.get("scope") == "two fresh ordinary C99 build directories on one hosted runner",
            "build scope")
    for key in ("source_commit", "source_tree"):
        require(hex_digest(report.get(key), 40), key)
    for key in ("compiler", "target", "linker", "host_arch", "source_date_epoch"):
        require(isinstance(report.get(key), str) and bool(report[key]), key)
    require(report["source_date_epoch"].isascii() and report["source_date_epoch"].isdigit(), "epoch")
    flags = report.get("flags")
    require(isinstance(flags, dict) and set(flags) == {"CPPFLAGS", "CFLAGS", "LDFLAGS", "LDLIBS"}
            and all(isinstance(v, str) for v in flags.values()), "flags")
    artifact = report.get("artifact")
    require(isinstance(artifact, dict) and set(artifact) ==
            {"path", "build_a_sha256", "build_b_sha256", "equal"}
            and artifact["path"] == "axi", "artifact")
    a, b = artifact["build_a_sha256"], artifact["build_b_sha256"]
    require(hex_digest(a, 64) and hex_digest(b, 64)
            and type(artifact["equal"]) is bool and artifact["equal"] == (a == b), "artifact digest record")
    sources = report.get("source_sha256")
    require(isinstance(sources, dict) and set(sources) == SOURCES
            and all(hex_digest(v, 64) for v in sources.values()), "source digests")
    return {
        "schema_version": 1, "kind": "axial-build-evidence",
        "profile": "ordinary-c99-same-runner", "signed": False,
        "revision": {"commit": report["source_commit"], "tree": report["source_tree"]},
        "results": {"two_build_digest_comparison": "match" if a == b else "mismatch"},
        "evidence": [{"path": EVIDENCE, "sha256": digest(payload)}],
    }


def produce(directory):
    payload = (directory / EVIDENCE).read_bytes()
    manifest = expected(json.loads(payload), payload)
    (directory / CAPSULE).write_bytes(encode(manifest))
    return manifest


def verify(directory):
    payload = (directory / EVIDENCE).read_bytes()
    manifest = json.loads((directory / CAPSULE).read_bytes())
    require(encode(manifest) == encode(expected(json.loads(payload), payload)),
            "capsule does not match build evidence")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("produce", "verify"))
    parser.add_argument("directory", type=pathlib.Path)
    args = parser.parse_args()
    try:
        manifest = (produce if args.operation == "produce" else verify)(args.directory)
    except (ValueError, OSError, TypeError, KeyError) as exc:
        parser.exit(1, "evidence error: %s\n" % exc)
    print("Unsigned metadata consistency: %s; no authority or provenance established." %
          manifest["results"]["two_build_digest_comparison"])


if __name__ == "__main__":
    main()
