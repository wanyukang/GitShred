#!/usr/bin/env python3
"""Deterministic helpers for the GitShred leaked-credential workflow."""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit


class GitShredError(Exception):
    """A user-actionable GitShred failure."""


@dataclass(frozen=True)
class Rule:
    kind: str
    label: str
    value: str


@dataclass(frozen=True)
class Candidate:
    kind: str
    label: str
    ref: str
    path: str
    line: int
    value: str
    context: str


DISCOVERY_PATTERNS = (
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("connection-string", re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s\"']+", re.I)),
    ("credential-assignment", re.compile(
        r"(?i)\b(?:password|passwd|secret|api[_-]?key|access[_-]?key|token|private[_-]?key)\b"
        r"\s*[:=]\s*[\"']?([^\s\"']{8,})"
    )),
)


def candidate_fingerprint(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def candidate_confidence(label):
    return {"private-key": 0.99, "connection-string": 0.96, "jwt": 0.92,
            "credential-assignment": 0.72}.get(label, 0.5)


def redact_candidate_line(line, value):
    return redact_text(line.strip(), [value])


def run_command(args, cwd=None, check=False):
    return subprocess.run(
        args,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=check,
    )


def run_git(repo, args, check=False):
    return run_command(["git", "-C", str(repo), *args], check=check)


def redacted_source(source):
    parsed = urlsplit(source)
    if not parsed.password:
        return source
    username = parsed.username or ""
    host = parsed.hostname or ""
    if parsed.port:
        host = f"{host}:{parsed.port}"
    netloc = f"{username}:<redacted>@{host}"
    return urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment))


def reject_embedded_credentials(source):
    parsed = urlsplit(source)
    if parsed.password:
        raise GitShredError("embedded_credentials_in_source")


def preview(value):
    if not value:
        return "<empty>"
    if len(value) >= 10:
        return f"{value[:3]}...{value[-3:]}"
    return f"{value[:1]}...{value[-1:]}"


def short_marker(value):
    return " short=true" if len(value) <= 5 else " short=false"


def redact_text(text, values):
    result = text
    for value in values:
        if value:
            result = result.replace(value, preview(value))
    return result


def parse_rules(path):
    rules = []
    for line_number, raw in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        parts = raw.split("\t", 2)
        if len(parts) != 3 or parts[0] not in {"text", "file"} or not parts[1] or not parts[2]:
            raise GitShredError(
                f"invalid_rule_line={line_number}; expected text<TAB>label<TAB>value or file<TAB>label<TAB>pattern"
            )
        rules.append(Rule(parts[0], parts[1], parts[2]))
    if not rules:
        raise GitShredError("no_rules")
    return rules


def ensure_git_repo(repo):
    result = run_git(repo, ["rev-parse", "--git-dir"])
    if result.returncode != 0:
        raise GitShredError(f"not_a_git_repository={repo}")


def ensure_bare_repo(repo):
    ensure_git_repo(repo)
    result = run_git(repo, ["rev-parse", "--is-bare-repository"])
    if result.stdout.strip() != "true":
        raise GitShredError("mirror_must_be_bare")


def resolve_bfg(explicit=None):
    candidate = explicit or os.environ.get("BFG_PATH")
    if candidate:
        path = Path(candidate)
        if not path.exists():
            return None
    else:
        command = shutil.which("bfg")
        if command:
            return [command]
        return None

    if path.suffix.lower() == ".jar":
        java = shutil.which("java")
        if not java:
            return None
        return [java, "-jar", str(path)]
    if not os.access(path, os.X_OK):
        return None
    return [str(path)]


def resolve_refs(repo, all_refs, refs_file):
    if all_refs and refs_file:
        raise GitShredError("choose_all_refs_or_refs_file")
    if not all_refs and not refs_file:
        raise GitShredError("refs_scope_required")
    if all_refs:
        result = run_git(repo, ["for-each-ref", "--format=%(refname)"])
        if result.returncode != 0:
            raise GitShredError("cannot_list_refs")
        # A mirror also contains refs/remotes/*, which are local tracking copies.
        # They are useful for explicit audit scopes but are not pushable repository refs.
        refs = [
            line for line in result.stdout.splitlines()
            if line.startswith(("refs/heads/", "refs/tags/"))
        ]
    else:
        refs = [
            line.strip()
            for line in Path(refs_file).read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
    if not refs:
        raise GitShredError("empty_refs_scope")
    for ref in refs:
        result = run_git(repo, ["rev-parse", "--verify", f"{ref}^{{commit}}"])
        if result.returncode != 0:
            raise GitShredError(f"invalid_ref={ref}")
    return refs


def detect_current_ref(repo):
    result = run_git(repo, ["symbolic-ref", "-q", "HEAD"])
    if result.returncode == 0 and result.stdout.strip():
        return result.stdout.strip()
    for candidate in ("refs/heads/main", "refs/heads/master"):
        result = run_git(repo, ["rev-parse", "--verify", f"{candidate}^{{commit}}"])
        if result.returncode == 0:
            return candidate
    return None


def detect_default_ref(repo):
    result = run_git(repo, ["symbolic-ref", "refs/remotes/origin/HEAD"])
    if result.returncode == 0 and result.stdout.strip():
        target = result.stdout.strip()
        if target.startswith("refs/remotes/origin/"):
            return "refs/heads/" + target.removeprefix("refs/remotes/origin/")
        return target
    for candidate in ("refs/heads/main", "refs/heads/master"):
        result = run_git(repo, ["rev-parse", "--verify", f"{candidate}^{{commit}}"])
        if result.returncode == 0:
            return candidate
    return None


def ref_commit(repo, ref):
    result = run_git(repo, ["rev-parse", f"{ref}^{{commit}}"])
    return result.stdout.strip()[:12] if result.returncode == 0 else "unknown"


def scan_text_rule(repo, ref, rule):
    result = run_git(repo, ["grep", "-n", "-F", "--text", "-e", rule.value, ref, "--"])
    if result.returncode not in {0, 1}:
        raise GitShredError(f"git_grep_failed={ref}")
    findings = []
    for line in result.stdout.splitlines():
        parts = line.split(":", 3)
        if len(parts) != 4:
            continue
        findings.append(
            "match "
            f"rule={rule.label} type=text ref={parts[0]} path={parts[1]} "
            f"commit={ref_commit(repo, ref)} line={parts[2]} preview={preview(rule.value)} "
            f"length={len(rule.value)}{short_marker(rule.value)} "
            f"context={redact_text(parts[3], [rule.value])}"
        )
    return findings


def scan_file_rule(repo, ref, rule):
    result = run_git(repo, ["ls-tree", "-r", "--name-only", ref])
    if result.returncode != 0:
        raise GitShredError(f"cannot_list_tree={ref}")
    findings = []
    for path in result.stdout.splitlines():
        if fnmatch.fnmatch(path, rule.value) or fnmatch.fnmatch(Path(path).name, rule.value):
            findings.append(
                f"match rule={rule.label} type=file ref={ref} commit={ref_commit(repo, ref)} path={path}"
            )
    return findings


def scan_objects(repo, rules):
    text_rules = [rule for rule in rules if rule.kind == "text"]
    if not text_rules:
        return []
    check = run_git(repo, ["cat-file", "--batch-all-objects", "--batch-check=%(objectname) %(objecttype)"])
    if check.returncode != 0:
        raise GitShredError("object_list_failed")
    findings = []
    for line in check.stdout.splitlines():
        parts = line.split()
        if len(parts) != 2 or parts[1] != "blob":
            continue
        blob = run_git(repo, ["cat-file", "blob", parts[0]])
        if blob.returncode != 0:
            continue
        for rule in text_rules:
            if rule.value in blob.stdout:
                findings.append(
                    f"object-match rule={rule.label} type=text object={parts[0][:12]} "
                    f"preview={preview(rule.value)} length={len(rule.value)}{short_marker(rule.value)}"
                )
    return findings


def scan_repo(repo, rules, refs):
    findings = []
    for ref in refs:
        for rule in rules:
            if rule.kind == "text":
                findings.extend(scan_text_rule(repo, ref, rule))
            else:
                findings.extend(scan_file_rule(repo, ref, rule))
    return findings


def discover_blob_candidates(repo, ref):
    result = run_git(repo, ["ls-tree", "-r", "--name-only", ref])
    if result.returncode != 0:
        raise GitShredError(f"cannot_list_tree={ref}")
    candidates = []
    for path in result.stdout.splitlines():
        blob = run_git(repo, ["show", f"{ref}:{path}"])
        if blob.returncode != 0 or "\x00" in blob.stdout:
            continue
        for line_number, line in enumerate(blob.stdout.splitlines(), 1):
            for label, pattern in DISCOVERY_PATTERNS:
                match = pattern.search(line)
                if not match:
                    continue
                value = match.group(1) if label == "credential-assignment" else match.group(0)
                if label == "private-key":
                    value = match.group(0)
                if len(value) < 8:
                    continue
                candidates.append(Candidate(
                    kind="text", label=label, ref=ref, path=path,
                    line=line_number, value=value, context=redact_candidate_line(line, value),
                ))
    return candidates


def candidate_key(candidate):
    return candidate.kind, candidate.label, candidate_fingerprint(candidate.value)


def command_discover(args):
    ensure_git_repo(args.repo)
    refs = resolve_refs(args.repo, args.all_refs, args.refs_file)
    grouped = {}
    for ref in refs:
        for candidate in discover_blob_candidates(args.repo, ref):
            key = candidate_key(candidate)
            occurrence = {
                "ref": ref,
                "commit": ref_commit(args.repo, ref),
                "path": candidate.path,
                "line": candidate.line,
                "context": candidate.context,
            }
            if key not in grouped:
                grouped[key] = {"candidate": candidate, "occurrences": []}
            grouped[key]["occurrences"].append(occurrence)
    candidates = [entry["candidate"] for entry in grouped.values()]
    store_records = []
    emit("status", "candidates" if candidates else "clean")
    emit("refs_count", str(len(refs)))
    emit("candidates_count", str(len(candidates)))
    for index, candidate in enumerate(candidates, 1):
        candidate_id = f"C-{index:04d}"
        occurrences = grouped[candidate_key(candidate)]["occurrences"]
        record = {
            "candidate_id": candidate_id,
            "kind": candidate.kind,
            "type": candidate.label,
            "ref": candidate.ref,
            "path": candidate.path,
            "line": candidate.line,
            "value": candidate.value,
            "context": candidate.context,
            "occurrences": occurrences,
        }
        store_records.append(record)
        print(json.dumps({
            "candidate_id": candidate_id,
            "kind": candidate.kind,
            "type": candidate.label,
            "ref": candidate.ref,
            "path": candidate.path,
            "line": candidate.line,
            "preview": preview(candidate.value),
            "length": len(candidate.value),
            "fingerprint": candidate_fingerprint(candidate.value),
            "confidence": candidate_confidence(candidate.label),
            "evidence": [f"pattern={candidate.label}", "value is redacted in output"],
            "context": candidate.context,
            "occurrences_count": len(occurrences),
            "occurrences": occurrences,
            "suggested_action": "replace_text",
            "human_decision": "pending",
        }, ensure_ascii=False))
    if args.store:
        store = Path(args.store).resolve()
        if store.exists() and store.stat().st_size != 0:
            raise GitShredError(f"candidate_store_exists={store}")
        store.parent.mkdir(parents=True, exist_ok=True)
        store.write_text(json.dumps({"version": 1, "candidates": store_records}, ensure_ascii=False), encoding="utf-8")
        store.chmod(0o600)
        emit("candidate_store", str(store))
    return 0


def command_export_rules(args):
    store = Path(args.store)
    if not store.is_file():
        raise GitShredError(f"candidate_store_missing={store}")
    try:
        payload = json.loads(store.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise GitShredError(f"candidate_store_invalid={store}") from error
    if payload.get("version") != 1 or not isinstance(payload.get("candidates"), list):
        raise GitShredError("candidate_store_version_unsupported")
    accepted = [item.strip() for item in args.accept.split(",") if item.strip()]
    if not accepted:
        raise GitShredError("accepted_candidates_required")
    by_id = {item.get("candidate_id"): item for item in payload["candidates"]}
    unknown = [candidate_id for candidate_id in accepted if candidate_id not in by_id]
    if unknown:
        raise GitShredError(f"unknown_candidate={unknown[0]}")
    output = Path(args.output).resolve()
    if output.exists():
        raise GitShredError(f"rules_destination_exists={output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    lines = []
    for candidate_id in accepted:
        item = by_id[candidate_id]
        if item.get("kind") != "text" or not item.get("value"):
            raise GitShredError(f"unsupported_candidate={candidate_id}")
        lines.append(f"text\t{candidate_id}-{item['type']}\t{item['value']}\n")
    output.write_text("".join(lines), encoding="utf-8")
    output.chmod(0o600)
    emit("status", "rules_created")
    emit("accepted_count", str(len(accepted)))
    emit("rules_path", str(output))
    return 0


def ensure_current_version_clean(repo, rules, current_ref=None):
    ref = current_ref or detect_current_ref(repo)
    if not ref:
        raise GitShredError("current_ref_unknown")
    findings = scan_repo(repo, rules, [ref])
    if findings:
        raise GitShredError(f"current_version_not_clean={ref}")
    default_ref = detect_default_ref(repo)
    if default_ref and default_ref != ref:
        findings = scan_repo(repo, rules, [default_ref])
        if findings:
            raise GitShredError(f"default_branch_not_clean={default_ref}")
    return ref, default_ref


def command_preflight(args):
    reject_embedded_credentials(args.source)
    source_path = Path(args.source)
    if source_path.exists():
        if not source_path.is_dir():
            raise GitShredError("local_source_must_be_directory")
        ensure_git_repo(source_path)
        source_type = "local"
    else:
        result = run_command(["git", "ls-remote", "--heads", args.source])
        if result.returncode != 0:
            raise GitShredError(f"remote_unreachable={redacted_source(args.source)}")
        source_type = "remote"

    git_version = run_command(["git", "--version"]).stdout.strip()
    bfg = resolve_bfg(args.bfg)
    emit("status", "ok")
    emit("source_type", source_type)
    emit("source", redacted_source(args.source))
    emit("git", git_version)
    emit("bfg_status", "found" if bfg else "missing")
    if bfg:
        emit("bfg_command", " ".join(bfg))
    for scanner in ("gitleaks", "trufflehog"):
        emit(f"{scanner}_status", "found" if shutil.which(scanner) else "missing")
    return 0


def command_prepare_mirror(args):
    reject_embedded_credentials(args.source)
    destination = Path(args.destination).resolve()
    if destination.exists():
        raise GitShredError(f"destination_exists={destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    result = run_command(["git", "clone", "--mirror", args.source, str(destination)])
    if result.returncode != 0:
        raise GitShredError(f"mirror_clone_failed={redacted_source(args.source)}")
    emit("status", "ok")
    emit("mirror_path", str(destination))
    emit("source", redacted_source(args.source))
    return 0


def command_scan(args):
    ensure_git_repo(args.repo)
    rules = parse_rules(args.rules)
    refs = resolve_refs(args.repo, args.all_refs, args.refs_file)
    findings = scan_repo(args.repo, rules, refs)
    emit("status", "matches" if findings else "clean")
    emit("refs_count", str(len(refs)))
    for finding in findings:
        print(finding)
    return 0


def command_verify(args):
    ensure_git_repo(args.repo)
    rules = parse_rules(args.rules)
    refs = resolve_refs(args.repo, args.all_refs, args.refs_file)
    findings = scan_repo(args.repo, rules, refs)
    emit("status", "failed" if findings else "verified")
    emit("refs_count", str(len(refs)))
    for finding in findings:
        print(finding)
    return 1 if findings else 0


def run_bfg_command(command, values):
    result = run_command(command)
    if result.returncode != 0:
        safe_stderr = redact_text(result.stderr.strip(), values)
        detail = f": {safe_stderr}" if safe_stderr else ""
        raise GitShredError(f"bfg_failed{detail}")


def execute_bfg(repo, rules, bfg, dry_run=False):
    text_rules = [rule for rule in rules if rule.kind == "text"]
    file_rules = [rule for rule in rules if rule.kind == "file"]
    if dry_run:
        emit("text_rules", str(len(text_rules)))
        emit("file_rules", str(len(file_rules)))
        return

    values = [rule.value for rule in rules]
    with tempfile.TemporaryDirectory(prefix="gitshred-") as temp_dir:
        if text_rules:
            replace_file = Path(temp_dir) / "replace-text.txt"
            replace_file.write_text(
                "".join(f"{rule.value}\n" for rule in text_rules),
                encoding="utf-8",
            )
            run_bfg_command(bfg + ["--replace-text", str(replace_file), str(repo)], values)
        for rule in file_rules:
            run_bfg_command(bfg + ["--delete-files", rule.value, str(repo)], values)
    emit("text_rules", str(len(text_rules)))
    emit("file_rules", str(len(file_rules)))


def delete_unselected_refs(repo, selected_refs):
    selected = set(selected_refs)
    result = run_git(repo, ["for-each-ref", "--format=%(refname)"])
    if result.returncode != 0:
        raise GitShredError("cannot_list_refs")
    all_refs = [line for line in result.stdout.splitlines() if line]
    for ref in all_refs:
        if ref not in selected:
            result = run_git(repo, ["update-ref", "-d", ref])
            if result.returncode != 0:
                raise GitShredError(f"cannot_delete_unselected_ref={ref}")


def push_selected_refs(source_repo, target_repo, selected_refs):
    for ref in selected_refs:
        result = run_command(
            ["git", "-C", str(source_repo), "push", "--force", str(Path(target_repo).resolve()), f"{ref}:{ref}"]
        )
        if result.returncode != 0:
            raise GitShredError(f"scoped_ref_update_failed={ref}")


def command_run_bfg(args):
    if not args.confirm:
        raise GitShredError("confirmation_required")
    ensure_bare_repo(args.mirror)
    rules = parse_rules(args.rules)
    selected_refs = resolve_refs(args.mirror, args.all_refs, args.refs_file)
    current_ref, default_ref = ensure_current_version_clean(args.mirror, rules, args.current_ref)
    bfg = resolve_bfg(args.bfg)
    if not bfg:
        raise GitShredError("bfg_unavailable")

    if args.dry_run:
        emit("status", "planned")
        emit("scope", "all" if args.all_refs else "selected")
        emit("refs_count", str(len(selected_refs)))
        emit("current_ref", current_ref)
        emit("default_ref", default_ref or "unknown")
        execute_bfg(args.mirror, rules, bfg, dry_run=True)
        return 0

    if args.all_refs:
        # Keep local remote-tracking copies out of the BFG rewrite and later push.
        delete_unselected_refs(args.mirror, selected_refs)
        execute_bfg(args.mirror, rules, bfg)
    else:
        with tempfile.TemporaryDirectory(prefix="gitshred-scoped-") as temp_dir:
            scoped_mirror = Path(temp_dir) / "scoped.git"
            clone = run_command(["git", "clone", "--mirror", str(args.mirror), str(scoped_mirror)])
            if clone.returncode != 0:
                raise GitShredError("scoped_mirror_clone_failed")
            delete_unselected_refs(scoped_mirror, selected_refs)
            execute_bfg(scoped_mirror, rules, bfg)
            push_selected_refs(scoped_mirror, args.mirror, selected_refs)
    emit("status", "ok")
    emit("scope", "all" if args.all_refs else "selected")
    emit("refs_count", str(len(selected_refs)))
    emit("current_ref", current_ref)
    emit("default_ref", default_ref or "unknown")
    return 0


def command_prune(args):
    if not args.confirm:
        raise GitShredError("confirmation_required")
    if args.aggressive and not args.confirm_aggressive:
        raise GitShredError("aggressive_confirmation_required")
    ensure_bare_repo(args.mirror)
    reflog = run_git(args.mirror, ["reflog", "expire", "--expire=now", "--all"])
    if reflog.returncode != 0:
        raise GitShredError("reflog_expire_failed")
    gc_args = ["gc", "--prune=now"]
    if args.aggressive:
        gc_args.append("--aggressive")
    gc = run_git(args.mirror, gc_args)
    if gc.returncode != 0:
        raise GitShredError("gc_failed")
    emit("status", "ok")
    emit("aggressive", "true" if args.aggressive else "false")
    if args.rules:
        rules = parse_rules(args.rules)
        findings = scan_objects(args.mirror, rules)
        emit("object_status", "matches" if findings else "clean")
        for finding in findings:
            print(finding)
        return 1 if findings else 0
    return 0


def command_object_scan(args):
    ensure_git_repo(args.repo)
    rules = parse_rules(args.rules)
    findings = scan_objects(args.repo, rules)
    emit("status", "matches" if findings else "clean")
    for finding in findings:
        print(finding)
    return 0


def command_push_guidance(args):
    ensure_git_repo(args.repo)
    refs = resolve_refs(args.repo, args.all_refs, args.refs_file)
    emit("status", "ok")
    emit("remote", args.remote)
    emit("scope", "all" if args.all_refs else "selected")
    if args.all_refs:
        print(f"push type=branches command=git push --force {args.remote} 'refs/heads/*:refs/heads/*'")
        print(f"push type=tags command=git push --force {args.remote} 'refs/tags/*:refs/tags/*'")
        return 0
    for ref in refs:
        if ref.startswith("refs/heads/"):
            print(f"push type=branch ref={ref} command=git push --force-with-lease {args.remote} {ref}:{ref}")
        elif ref.startswith("refs/tags/"):
            print(f"push type=tag ref={ref} command=git push --force {args.remote} {ref}:{ref}")
        else:
            print(f"push type=ref ref={ref} command=git push --force {args.remote} {ref}:{ref}")
    return 0


def emit(key, value):
    print(f"{key}={value}")


def build_parser():
    parser = argparse.ArgumentParser(prog="gitshred")
    subparsers = parser.add_subparsers(dest="command", required=True)

    preflight = subparsers.add_parser("preflight")
    preflight.add_argument("source")
    preflight.add_argument("--bfg")
    preflight.set_defaults(handler=command_preflight)

    prepare = subparsers.add_parser("prepare-mirror")
    prepare.add_argument("source")
    prepare.add_argument("--destination", required=True)
    prepare.set_defaults(handler=command_prepare_mirror)

    for name, handler in (("scan", command_scan), ("verify", command_verify)):
        command = subparsers.add_parser(name)
        command.add_argument("repo")
        command.add_argument("rules")
        scope = command.add_mutually_exclusive_group(required=True)
        scope.add_argument("--all", dest="all_refs", action="store_true")
        scope.add_argument("--refs-file")
        command.set_defaults(handler=handler)

    discover = subparsers.add_parser(
        "discover",
        help="read-only candidate discovery for likely credentials; output requires human confirmation",
    )
    discover.add_argument("repo")
    discover_scope = discover.add_mutually_exclusive_group(required=True)
    discover_scope.add_argument("--all", dest="all_refs", action="store_true")
    discover_scope.add_argument("--refs-file")
    discover.add_argument("--store", help="write a restricted local candidate store for later approval")
    discover.set_defaults(handler=command_discover)

    export_rules = subparsers.add_parser(
        "export-rules",
        help="turn explicitly accepted candidate IDs into a restricted BFG rules file",
    )
    export_rules.add_argument("store")
    export_rules.add_argument("--accept", required=True, help="comma-separated candidate IDs accepted by the user")
    export_rules.add_argument("--output", required=True)
    export_rules.set_defaults(handler=command_export_rules)

    run_bfg = subparsers.add_parser("run-bfg")
    run_bfg.add_argument("mirror")
    run_bfg.add_argument("rules")
    run_scope = run_bfg.add_mutually_exclusive_group(required=True)
    run_scope.add_argument("--all", dest="all_refs", action="store_true")
    run_scope.add_argument("--refs-file")
    run_bfg.add_argument("--bfg")
    run_bfg.add_argument("--current-ref")
    run_bfg.add_argument("--confirm", action="store_true")
    run_bfg.add_argument("--dry-run", action="store_true")
    run_bfg.set_defaults(handler=command_run_bfg)

    prune = subparsers.add_parser("prune")
    prune.add_argument("mirror")
    prune.add_argument("--rules")
    prune.add_argument("--confirm", action="store_true")
    prune.add_argument("--aggressive", action="store_true")
    prune.add_argument("--confirm-aggressive", action="store_true")
    prune.set_defaults(handler=command_prune)

    object_scan = subparsers.add_parser("object-scan")
    object_scan.add_argument("repo")
    object_scan.add_argument("rules")
    object_scan.set_defaults(handler=command_object_scan)

    push_guidance = subparsers.add_parser("push-guidance")
    push_guidance.add_argument("repo")
    push_scope = push_guidance.add_mutually_exclusive_group(required=True)
    push_scope.add_argument("--all", dest="all_refs", action="store_true")
    push_scope.add_argument("--refs-file")
    push_guidance.add_argument("--remote", default="origin")
    push_guidance.set_defaults(handler=command_push_guidance)
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.handler(args)
    except (GitShredError, OSError) as error:
        print(f"error={error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
