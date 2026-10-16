# Bundled CLI

Run the CLI with Python 3 and Git. BFG is discovered from --bfg, BFG_PATH, or PATH; GitShred never downloads it.

## Commands

    gitshred.py preflight SOURCE [--bfg PATH]
    gitshred.py prepare-mirror SOURCE --destination MIRROR.git
    gitshred.py scan REPO RULES.tsv (--all | --refs-file REFS.txt)
    gitshred.py discover REPO (--all | --refs-file REFS.txt)
    gitshred.py export-rules CANDIDATES.json --accept C-0001,C-0007 --output RULES.tsv
    gitshred.py verify REPO RULES.tsv (--all | --refs-file REFS.txt)
    gitshred.py run-bfg MIRROR.git RULES.tsv (--all | --refs-file REFS.txt) --bfg PATH --confirm [--dry-run]
    gitshred.py prune MIRROR.git --confirm [--rules RULES.tsv] [--aggressive --confirm-aggressive]
    gitshred.py object-scan MIRROR.git RULES.tsv
    gitshred.py push-guidance MIRROR.git (--all | --refs-file REFS.txt) [--remote origin]

## Exit codes

- 0: completed or verified clean;
- 1: verification found a confirmed rule;
- 2: input, dependency, confirmation, or execution error.

The CLI uses line-oriented output such as status=verified and match lines. It redacts text matches before printing them. `--all` resolves `refs/heads/*` and `refs/tags/*`; `refs/remotes/*` tracking copies require an explicit refs file.

`discover` is read-only candidate discovery. Its JSON candidates stay `human_decision=pending`; the command never creates rules or invokes BFG. With `--store`, it writes the exact candidate values and all occurrences to a user-selected file outside the repository with mode `0600`; an existing empty file is accepted, while a non-empty file is never overwritten. The path must be treated as sensitive working material and removed after the run.

`export-rules` is the approval bridge. It accepts only explicitly named candidate IDs and creates a mode `0600` rules file. The conversational skill should present candidates in natural language, obtain explicit acceptance, invoke this bridge, and then continue through the existing dry-run and BFG confirmation gates. `push-guidance --all` emits separate heads and tags pushes and never emits a raw `git push --mirror` command.

The run-bfg command checks the current ref before execution. It rejects a confirmed rule still present in that ref. A refs-file scope is executed in a temporary scoped mirror, then only the selected refs are updated in the main isolated mirror.
