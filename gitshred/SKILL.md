---
name: gitshred
description: Use when a user asks in natural language to find, inspect, or clean possible leaked Git credentials such as passwords, tokens, private keys, JWTs, connection strings, or credential files. Discover likely candidates across visible repository history, explain evidence and uncertainty, obtain human approval for each cleanup action, then use the isolated-mirror BFG workflow; clarify requests about repository size, ordinary PII, or vague secrets before any rewrite.
---

# GitShred

Use GitShred as a conversational incident workflow. Interpret natural language such as “帮我找出仓库历史里可能泄露的凭据，列出来让我确认，确认后清理” as a request to discover first. Treat BFG as the execution backend, not the user-facing interaction. Keep the workflow auditable: inspect first, explain candidates, obtain confirmations, rewrite only an isolated mirror, verify, and report unresolved work.

## Workflow

### 1. Establish the incident

Confirm that the request concerns credentials committed to Git history:

- passwords, API/OAuth/CI tokens, cloud access keys, private keys, JWTs, connection-string credentials, or credential files;
- not repository-size cleanup, large blobs, ordinary PII, or vague business secrets.

For an ambiguous cleanup request, ask whether the user means leaked-credential remediation before scanning or rewriting. A request to “检查有没有敏感信息” authorizes read-only discovery, not cleanup. Never treat a detector or model result as a confirmed target.

### 2. Run read-only preflight

Accept a local repository path or a remote URL. Use the user's existing Git credential helper for remote access; never put credentials in command arguments or output.

Run:

    scripts/gitshred.py preflight SOURCE [--bfg BFG_PATH]

Stop if the source is unreachable, is not a Git repository, or BFG is unavailable. Do not download or install BFG. An installed gitleaks or trufflehog may be used as an optional read-only candidate finder, but its output still needs confirmation.

### 3. Discover, explain, and confirm candidates

Run the bundled read-only candidate discovery over the requested visible refs. It checks structured credential patterns, credential assignments, connection strings, JWTs, private-key markers, and high-risk configuration content. Use an installed gitleaks or trufflehog only as an additional candidate source when available. The discovery implementation is `scripts/gitshred.py discover`; users should not need to know or invoke that command directly. Store exact candidate values only in a mode-0600 file outside the repository, and remove that file after rules are generated and verified.

For each candidate, explain what was found, where it occurs, which refs and commits contain it, why it may be a credential, the uncertainty, and the proposed action. Group repeated occurrences of the same value when possible. Keep exact values local and redacted in output. An LLM classifier may classify and explain candidates, but it must not authorize cleanup.

Ask the user to accept, reject, or defer each candidate or explicitly named group. Only accepted candidates become rules. A discovery result with `human_decision=pending` is never executable.

After acceptance, use `scripts/gitshred.py export-rules STORE --accept C-0001,C-0007 --output RULES.tsv` to create the exact rules file. Never hand-copy a redacted preview into a rule. Then use the rules format in references/rules.md.

Show every candidate with its file path, commit/ref, line context, credential type, length, and a bounded preview. Keep the candidate actionable: use the redaction rules in references/rules.md, and never print the complete credential in standard output.

Apply the preservation policy before creating rules:

- For mixed configuration files such as .env, YAML, JSON, properties, and connection-string files, preserve the file by default and create one text rule per confirmed credential value.
- For standalone credential files such as private keys or dedicated token files, propose file deletion when the file has no non-secret business content, but still use the file-deletion confirmation gate.
- When the user says “clean .env” or names a configuration file without specifying an action, proceed with the preservation path: inspect the file, show credential candidates, and ask for confirmation of the exact text rules.
- Treat every file deletion as an exceptional destructive action. Even when the user requests it, restate the exact file patterns and refs that will be deleted, explain the irreversible impact, and require a separate final confirmation immediately before execution.

Before proceeding, obtain explicit confirmation for:

1. each text value or file pattern to clean;
2. whether the current default-branch code is already clean;
3. the refs scope: user-selected refs or all visible refs;
4. creating and rewriting an isolated mirror;
5. running BFG and object cleanup.

### 4. Prepare the isolated mirror

Create a new destination that does not already exist:

    scripts/gitshred.py prepare-mirror SOURCE --destination MIRROR.git

Never rewrite the user's working repository. Preserve the source as a recovery point. Treat an existing bare mirror as non-unique until the user confirms otherwise.

### 5. Check the current version

Scan the selected refs before BFG. If a confirmed text rule still occurs in the default branch HEAD or current code, stop. Ask the user to remove or replace it and create a clean commit first. Do not use BFG's force-overwrite behavior to solve the current version.

Use:

    scripts/gitshred.py scan MIRROR.git RULES.tsv --all
    scripts/gitshred.py verify MIRROR.git RULES.tsv --refs-file REFS.txt

Choose exactly one scope: --all or --refs-file. `--all` means all pushable repository refs (`refs/heads/*` and `refs/tags/*`); local `refs/remotes/*` tracking copies are excluded from the default rewrite and push scope. Include a remote-tracking ref only when the user explicitly names it in a refs file, and state that it is an audit-only local copy. If a user chooses a subset, state that unselected refs remain unverified.

### 6. Plan and execute BFG

Use only these first-version actions:

- text rules through BFG --replace-text;
- file rules through BFG --delete-files.

Use text replacement for credentials inside a configuration file. Use file deletion only for a user-confirmed standalone credential file or an explicitly confirmed whole-file deletion that passed the separate deletion confirmation. Every file rule must pass that final deletion confirmation. Do not perform large-file cleanup, broad directory deletion, or automatic rule inference. Review the dry plan first:

    scripts/gitshred.py run-bfg MIRROR.git RULES.tsv --all --bfg BFG_PATH --confirm --dry-run

After the user confirms the plan, execute it:

    scripts/gitshred.py run-bfg MIRROR.git RULES.tsv --all --bfg BFG_PATH --confirm

If the case exceeds BFG's reliable capabilities, stop and explain the upgrade path. Do not silently select another history-rewrite tool.

### 7. Reclaim local mirror objects and verify

After BFG, reclaim reflogs and unreachable objects only in the isolated mirror:

    scripts/gitshred.py prune MIRROR.git --confirm --rules RULES.tsv

Require a separate confirmation for --aggressive --confirm-aggressive. Then verify every selected ref and the mirror object state. Keep these states separate:

- refs no longer contain the confirmed rules;
- the isolated mirror has reclaimed old objects;
- the object library no longer contains confirmed text rules;
- the credential has been revoked or rotated;
- the remote and downstream clones have been updated.

### 8. Deliver the remediation summary

Give an in-conversation summary using references/summary.md. Include the source, mirror, confirmed rules in redacted form, scope, actions, verification, and unresolved work. Do not write a report file unless the user explicitly asks for one.

Never claim the incident is closed until the user confirms credential revocation or rotation. Generate precise push guidance for the selected refs:

    scripts/gitshred.py push-guidance MIRROR.git --refs-file REFS.txt --remote origin
    scripts/gitshred.py push-guidance MIRROR.git --all --remote git@git.example/repo.git

Do not push automatically. Suggest force-with-lease for local branch scopes. For all refs, review the generated heads/tags commands and the explicit source remote before pushing. A mirror's cloned `origin` may point to the local source path.

## Completion criteria

Finish only when the summary states all of the following:

- the exact confirmed rules and refs scope are recorded;
- BFG executed or the blocking reason is explicit;
- selected refs were re-scanned after object reclaim;
- current-version cleanliness is known;
- credential rotation status is known or marked unresolved;
- no remote push or downstream sync is implied to have happened automatically.

## Resources

- Read references/rules.md when creating rules, showing candidates, or choosing refs.
- Read references/summary.md when composing the final in-conversation summary.
- Read references/scripts.md when invoking or troubleshooting the bundled CLI.
