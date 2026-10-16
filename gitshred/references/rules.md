# Rules, scope, and redaction

## Rules file

Use a UTF-8 tab-separated file. Each non-comment line has three fields:

    text<TAB>label<TAB>exact secret value
    file<TAB>label<TAB>filename or glob pattern

Use text for an exact confirmed value. Use file for a confirmed credential file such as .env.production or id_rsa. Keep one rule per line. Do not put tabs in values. Keep the rules file outside the target repository when possible, and remove it after the run.

The CLI ignores blank lines and lines beginning with #. It rejects malformed or empty rule files.

## Candidate display

Make every candidate actionable by showing its path, ref, line, context, type, and bounded preview:

- length 10 or more: first 3 and last 3 characters;
- length 6-9: first 1 and last 1 characters;
- length 5 or less: first 1 and last 1 characters, marked as short;
- structured credentials may add safe fields such as JWT header values, key type/fingerprint, or connection host/database;
- standard output never prints the complete secret.

Use the same controlled preview in the remediation summary. Do not reduce normal candidate output to a hash-only label; users need to match a finding to a real commit.

## Preservation policy

Treat a configuration file and a standalone credential file differently:

- Mixed configuration: .env, YAML, JSON, properties, and connection-string files usually contain both usable configuration and credentials. Preserve the file and use text rules for each confirmed credential.
- Standalone credential: private keys, dedicated token files, and credential files with no non-secret business content can be deleted after explicit confirmation.

Treat “clean .env” as the preservation path: inspect the file, identify credential candidates, and create text rules for confirmed values. Do not ask the user to choose deletion merely because the filename is .env.

Every file deletion is exceptional and requires a second confirmation immediately before execution. Restate the exact file patterns and refs, explain the irreversible impact, and proceed only after the user confirms that destructive action.

## Scope

Use exactly one scope:

- --all: every visible ref in the mirror, including branches and tags;
- --refs-file REFS.txt: only the refs listed in the file.

If the user knows the affected refs, honor the selected scope. If the user is unsure or requests a full check, use --all. A subset result must state that unselected refs remain unverified.

## Actions

The first version maps rules to exactly two BFG actions:

- text -> --replace-text;
- file -> --delete-files.

Do not convert a scanner result into a rule without confirmation.
