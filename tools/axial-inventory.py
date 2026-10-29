#!/usr/bin/env python3
"""Inventory Axial's immutable source registries; never execute product code.

Examples:
  python3 tools/axial-inventory.py --repo . --ref COMMIT --output inventory.json
  python3 tools/axial-inventory.py --snapshot source-snapshot.json \
      --sources mirror --output inventory.json

The parser intentionally accepts only the current literal registry grammar.
An unsupported table shape is an error, not an empty or partial inventory.
"""
import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath


class InventoryError(Exception):
    pass


INSPECT = ("src/axi_bc.h", "src/axi_builtin_registry.h",
           "src/axi_cap_table.h", "src/axi_cap_table.c")
Q = r'"(?:[^"\\]|\\.)*"'
IDENT = r"[A-Za-z_][A-Za-z0-9_]*"
HEX40 = re.compile(r"[0-9a-f]{40}\Z")


def require(condition, message):
    if not condition:
        raise InventoryError(message)


def git(root, *args):
    result = subprocess.run(["git", "-C", str(root), *args],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode:
        raise InventoryError("git: " + result.stderr.decode("utf-8", "replace").strip())
    return result.stdout


def object_id(kind, data):
    return hashlib.sha1(kind.encode("ascii") + b" " + str(len(data)).encode("ascii")
                        + b"\0" + data).hexdigest()


def validate_entries(entries, expected_tree):
    require(isinstance(entries, list) and entries, "source manifest has no entries")
    paths, root = {}, {}
    for item in entries:
        require(isinstance(item, dict), "invalid manifest entry")
        path, mode, oid = item.get("path"), item.get("mode"), item.get("sha")
        require(isinstance(path, str) and path and "\0" not in path
                and not path.startswith("/")
                and all(p not in ("", ".", "..") for p in path.split("/")),
                "manifest contains an invalid relative path")
        require(path not in paths, "duplicate manifest path: " + path)
        require(item.get("type") == "blob" and mode in ("100644", "100755", "120000")
                and isinstance(oid, str) and HEX40.fullmatch(oid),
                "unsupported tree entry: " + path)
        require(type(item.get("size")) is int and item["size"] >= 0,
                "missing blob size: " + path)
        paths[path] = item
        node = root
        parts = path.split("/")
        for component in parts[:-1]:
            require(not isinstance(node.get(component), tuple), "tree path collision: " + path)
            node = node.setdefault(component, {})
        require(parts[-1] not in node, "tree path collision: " + path)
        node[parts[-1]] = (mode, oid)

    def tree_oid(node):
        ordered = sorted(node.items(), key=lambda pair:
                         pair[0].encode("utf-8") + (b"/" if isinstance(pair[1], dict) else b""))
        body = bytearray()
        for name, entry in ordered:
            mode, oid = ("40000", tree_oid(entry)) if isinstance(entry, dict) else entry
            body.extend(mode.encode("ascii") + b" " + name.encode("utf-8")
                        + b"\0" + bytes.fromhex(oid))
        return object_id("tree", bytes(body))

    require(tree_oid(root) == expected_tree, "manifest entries do not match the declared Git tree")
    return paths


def load_source(args):
    if args.snapshot:
        require(args.sources is not None and args.ref is None,
                "--snapshot requires --sources and does not accept --ref")
        manifest = json.loads(Path(args.snapshot).read_text(encoding="utf-8"))
        require(isinstance(manifest, dict), "snapshot must be a JSON object")
        require(manifest.get("schema") == "axial.source-snapshot.v1", "unsupported snapshot schema")
        require(manifest.get("git_object_format") == "sha1", "only Git SHA-1 snapshots are supported")
        acquisition = manifest.get("acquisition")
        require(isinstance(acquisition, dict) and acquisition.get("truncated") is False,
                "snapshot must explicitly declare a complete tree")
        repository = manifest.get("repository")
        commit, tree = manifest.get("commit"), manifest.get("tree_sha")
        entries = manifest.get("entries")
        base = Path(args.sources).resolve()

        def read(path):
            candidate = (base / path).resolve()
            require(candidate.is_relative_to(base), "source escapes the mirror: " + path)
            return candidate.read_bytes()
    else:
        require(args.ref and args.sources is None, "--repo requires --ref and does not accept --sources")
        repository = args.repository
        commit = git(args.repo, "rev-parse", "--verify", "--end-of-options",
                     args.ref + "^{commit}").decode("ascii").strip()
        tree = git(args.repo, "rev-parse", commit + "^{tree}").decode("ascii").strip()
        entries = []
        for record in git(args.repo, "ls-tree", "-r", "-l", "-z", "--full-tree", commit).split(b"\0"):
            if not record:
                continue
            header, path = record.split(b"\t", 1)
            mode, kind, oid, size = header.decode("ascii").split()
            require(kind == "blob", "unsupported non-blob entry in source tree")
            entries.append(dict(path=path.decode("utf-8"), mode=mode, type=kind,
                                sha=oid, size=int(size)))

        def read(path):
            return git(args.repo, "show", commit + ":" + path)

    require(isinstance(repository, str) and repository, "missing repository identity")
    require(isinstance(commit, str) and HEX40.fullmatch(commit)
            and isinstance(tree, str) and HEX40.fullmatch(tree), "invalid commit/tree identity")
    entries = validate_entries(entries, tree)
    content, inspected = {}, []
    for path in INSPECT:
        require(path in entries, "registry source absent from commit: " + path)
        require(entries[path]["mode"] != "120000", "registry source must be a regular file: " + path)
        data = read(path)
        require(len(data) == entries[path]["size"] and object_id("blob", data) == entries[path]["sha"],
                "source blob mismatch: " + path)
        content[path] = data.decode("utf-8")
        inspected.append(dict(path=path, blob_sha=entries[path]["sha"],
                              sha256=hashlib.sha256(data).hexdigest(), size_bytes=len(data)))
    return repository, commit, tree, entries, content, inspected


def macro_rows(source, name):
    lines = source.splitlines()
    definitions = [i for i, line in enumerate(lines)
                   if re.match(r"\s*#define\s+" + name + r"\b", line)]
    starts = [i for i, line in enumerate(lines)
              if re.fullmatch(r"\s*#define\s+" + name + r"\(X\)\s*\\\s*", line)]
    require(len(definitions) == 1 and definitions == starts,
            "expected one literal X-macro: " + name)
    result, i = [], starts[0] + 1
    while i < len(lines):
        line = lines[i].strip()
        more = line.endswith("\\")
        if more:
            line = line[:-1].rstrip()
        require(line.startswith("X(") and line.endswith(")"), "unsupported row in " + name)
        result.append(line)
        if not more:
            return result
        i += 1
    raise InventoryError("unterminated X-macro: " + name)


def match_row(pattern, row, table):
    match = re.fullmatch(pattern, row)
    require(match is not None, "unsupported literal row in " + table)
    return match.groups()


def unique(rows, key, label):
    values = [row[key] for row in rows]
    require(len(values) == len(set(values)), "duplicate " + label)


def literal(value):
    # Current registries use the intersection of C and JSON string escapes.
    return json.loads(value)


def parse_opcodes(source):
    result = []
    pattern = rf"X\(\s*({IDENT})\s*,\s*({Q})\s*,\s*({IDENT})\s*,\s*(\d+)\s*,\s*({Q})\s*\)"
    for ordinal, row in enumerate(macro_rows(source, "AXB_OPCODES")):
        symbol, name, operands, cost, doc = match_row(pattern, row, "AXB_OPCODES")
        result.append(dict(ordinal=ordinal, enum_symbol="OP_" + symbol, name=literal(name),
                           operands=operands, fuel=int(cost), description=literal(doc)))
    unique(result, "enum_symbol", "opcode symbol")
    unique(result, "name", "opcode name")
    return result


def table_body(source, pattern, name):
    matches = re.findall(pattern, source, re.S)
    require(len(matches) == 1, "expected one literal table: " + name)
    return matches[0]


def parse_capabilities(header, source):
    body = table_body(header, r"typedef\s+enum\s*\{([^{}]*)\}\s*axi_cap_kind\s*;", "axi_cap_kind")
    body = re.sub(r"/\*.*?\*/", "", body, flags=re.S)
    raw = [part.strip() for part in body.split(",") if part.strip()]
    require(raw and raw[0] == "CAP_NONE = 0" and raw[-1] == "CAP__COUNT",
            "unsupported capability enum boundaries")
    symbols = ["CAP_NONE"] + raw[1:-1]
    require(all(re.fullmatch(r"CAP_[A-Z_]+", name) for name in symbols), "unsupported capability enum value")
    require(len(set(symbols)) == len(symbols), "duplicate capability enum")
    info = table_body(source, r"static\s+const\s+axi_cap_info\s+CAP_INFO\[CAP__COUNT\]\s*=\s*\{(.*?)\n\};", "CAP_INFO")
    entries = {}
    pattern = rf"\[({IDENT})\]\s*=\s*\{{\s*({IDENT})\s*,\s*({Q})\s*,\s*({Q})\s*\}},"
    for line in info.splitlines():
        if not line.strip():
            continue
        index, kind, host, name = match_row(pattern, line.strip(), "CAP_INFO")
        require(index == kind and kind not in entries, "inconsistent CAP_INFO key")
        entries[kind] = dict(symbol=kind, name=literal(name), host_verb=literal(host))
    require(set(entries) == set(symbols), "CAP_INFO does not cover the capability enum")
    caps = [dict(enum_value=i, **entries[name]) for i, name in enumerate(symbols) if name != "CAP_NONE"]
    unique(caps, "name", "capability name")
    require(all(row["name"] and row["host_verb"] for row in caps), "empty capability name")
    methods_body = table_body(source, r"static\s+const\s+axi_cap_method\s+CAP_METHODS\[\]\s*=\s*\{(.*?)\n\};", "CAP_METHODS")
    methods = []
    pattern = rf"\{{\s*({IDENT})\s*,\s*({Q})\s*,\s*({Q})\s*,\s*({Q})\s*\}},"
    for line in methods_body.splitlines():
        if not line.strip():
            continue
        cap, method, effect, ret = match_row(pattern, line.strip(), "CAP_METHODS")
        require(cap in entries and cap != "CAP_NONE", "unknown method capability")
        methods.append(dict(capability=cap, method=literal(method), effect=literal(effect), returns=literal(ret)))
    require(methods, "CAP_METHODS is empty")
    require(len({(m["capability"], m["method"]) for m in methods}) == len(methods), "duplicate capability method")
    return caps, sorted(methods, key=lambda m: (m["capability"], m["method"]))


def parse_builtins(source, caps):
    result, known = [], {cap["symbol"]: cap["name"] for cap in caps}
    pattern = (rf"X\(\s*({Q})\s*,\s*(\d+)\s*,\s*({IDENT})\s*,\s*({IDENT})\s*,\s*({IDENT})"
               rf"\s*,\s*({IDENT})\s*,\s*({IDENT})\s*,\s*({Q}|NULL)\s*,\s*([01])\s*\)")
    for row in macro_rows(source, "AXI_BUILTIN_REGISTRY"):
        name, arity, p0, p1, p2, ret, cap, capstr, flag = match_row(pattern, row, "AXI_BUILTIN_REGISTRY")
        n = int(arity)
        require(n <= 3, "builtin arity exceeds literal registry slots")
        capname = None if capstr == "NULL" else literal(capstr)
        require((cap == "CAP_NONE" and capname is None)
                or (cap in known and known[cap] == capname), "builtin capability does not match CAP_INFO")
        result.append(dict(name=literal(name), arity=n, arguments=[p0, p1, p2][:n],
                           returns=ret, capability=cap, capability_name=capname,
                           capability_gated=flag == "1"))
    unique(result, "name", "builtin name")
    return sorted(result, key=lambda row: row["name"])


def inventory(args):
    repository, commit, tree, entries, source, inspected = load_source(args)
    opcodes = parse_opcodes(source[INSPECT[0]])
    caps, methods = parse_capabilities(source[INSPECT[2]], source[INSPECT[3]])
    builtins = parse_builtins(source[INSPECT[1]], caps)
    files = [dict(path=path, blob_sha=item["sha"], mode=item["mode"], size_bytes=item["size"])
             for path, item in sorted(entries.items()) if PurePosixPath(path).suffix in (".c", ".h")]
    product = [item for item in files if item["path"].split("/", 1)[0] in ("src", "include", "vendor")]
    refs = {}
    for path, text in source.items():
        for target in re.findall(r"(?:docs|tools)/[A-Za-z0-9_./-]+\.(?:tsv|py)", text):
            refs.setdefault(target, set()).add(path)
    references = [dict(path=path, referenced_by=sorted(owners), present_in_commit=path in entries)
                  for path, owners in sorted(refs.items())]
    units = {}
    for item in product:
        stem = str(PurePosixPath(item["path"]).with_suffix(""))
        units.setdefault(stem, []).append(item["path"])
    return dict(schema="axial.inventory.v1", repository=repository, commit=commit, tree_sha=tree,
                scope=dict(kind="static_source_inventory", runtime_availability="not_evaluated",
                           product_filter=".c/.h paths under src/, include/, vendor/",
                           product_filter_is_checker_identity=False,
                           builtin_flag="capability_gated is the checker impurity flag, not a fuel price",
                           effect_scope="declared capability verbs and method mappings; backend support is not inferred"),
                verification=dict(tree_manifest_matches=True, inspected_blobs_match=True,
                                  product_code_executed=False, runtime_tests_run=False),
                counts=dict(tracked_blobs=len(entries), c_h_files=len(files), product_c_h_files=len(product),
                            source_units=len(units), opcodes=len(opcodes), builtins=len(builtins),
                            capabilities=len(caps), capability_methods=len(methods)),
                c_h_files=files, product_c_h_files=product,
                source_units=[dict(stem=stem, files=paths) for stem, paths in sorted(units.items())],
                inspected_sources=inspected, opcodes=opcodes, builtins=builtins,
                capabilities=caps, capability_methods=methods, referenced_sources=references)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--repo", type=Path, help="Git checkout; sources are read from the immutable ref")
    mode.add_argument("--snapshot", type=Path, help="complete axial.source-snapshot.v1 manifest")
    parser.add_argument("--ref", help="commit or ref resolved once to a full commit SHA")
    parser.add_argument("--sources", type=Path, help="mirror containing the inspected sources")
    parser.add_argument("--repository", default="FermiHart/axial", help="repository identity for --repo mode")
    parser.add_argument("--output", type=Path, help="JSON destination; default stdout")
    args = parser.parse_args()
    try:
        result = json.dumps(inventory(args), ensure_ascii=False, sort_keys=True, indent=2) + "\n"
        if args.output:
            args.output.write_text(result, encoding="utf-8")
        else:
            sys.stdout.write(result)
        return 0
    except (InventoryError, OSError, ValueError, UnicodeError, KeyError, TypeError) as error:
        print("axial-inventory: " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
