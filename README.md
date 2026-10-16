# GitShred

GitShred is a Codex skill for investigating and remediating suspected credentials committed to Git history.

The skill is designed for a conversational workflow. A user describes the security concern in natural language, GitShred discovers and explains likely candidates, the user authorizes the specific cleanup actions, and BFG performs the approved history rewrite inside an isolated mirror.

## Quick start

Invoke the skill explicitly or describe the intent directly:

```text
$gitshred

Please inspect this repository's Git history for possible leaked passwords,
tokens, private keys, and connection strings. Show me redacted candidates
with their locations and reasons. Wait for my approval before changing anything.
```

GitShred should then:

1. establish that the request concerns committed credential material;
2. run a read-only preflight;
3. discover and group likely candidates across the requested visible history;
4. explain the evidence, uncertainty, locations, and suggested action for each candidate;
5. wait for the user to accept, reject, or defer named candidates;
6. prepare an auditable cleanup plan;
7. ask for the confirmations required before rewriting history;
8. execute BFG only in a new isolated mirror;
9. reclaim mirror objects and verify the selected refs and object library;
10. report the result, unresolved work, rotation status, and reviewed push guidance.

A user can respond with a decision such as:

```text
Accept C-0001 and C-0004. Defer the rest. Clean all branches and tags.
```

The user does not need to copy complete secrets or construct BFG rules manually. GitShred maps accepted candidate IDs to exact rules in a restricted temporary store, then continues through the existing BFG workflow.

## What the skill does

GitShred combines three responsibilities:

- **Discovery:** inspect the repository's visible Git history for likely passwords, API/OAuth/CI tokens, cloud keys, private keys, JWTs, connection strings, and credential files;
- **Reasoning:** use file context, field names, history locations, repeated occurrences, detector evidence, and optional LLM classification to explain whether a candidate is likely to be a credential and what action fits it;
- **Remediation:** convert only user-approved candidates into BFG rules, rewrite an isolated mirror, reclaim old objects, verify the result, and prepare push guidance.

The LLM contributes semantic interpretation and explanation. It can classify candidates, group repeated occurrences, identify likely placeholders or examples, and suggest text replacement or file deletion. Its judgment is evidence for review; it is never authorization.

The user remains the authority for:

- which candidates are real credentials;
- which refs are in scope;
- whether the current and default branches are clean;
- whether a configuration value should be replaced or a standalone file should be deleted;
- whether an isolated mirror may be rewritten;
- whether BFG and object reclamation may run;
- whether a rewritten mirror may be pushed to a remote.

BFG is the current execution backend. It performs the approved text replacement or file deletion after the conversational review is complete.

## Interaction model

GitShred treats a natural-language request according to its intent:

- “Check whether this repository contains leaked credentials” starts a read-only investigation.
- “List possible secrets and let me choose” starts discovery and candidate review.
- “Remove this confirmed token from history” starts a targeted remediation flow.
- “Clean up the repository” is ambiguous and requires clarification before any history rewrite.

Discovery results remain pending until the user names the candidates to accept. A detector match, scanner result, or LLM classification never becomes a cleanup rule automatically.

Candidates are shown with enough information for a decision:

- candidate ID;
- credential type;
- file path, ref, commit, and line;
- all grouped occurrences where the same value repeats;
- bounded preview, length, and fingerprint;
- evidence and uncertainty;
- suggested action.

Complete credential values stay out of normal conversational output. Exact values are kept only in a restricted working file outside the target repository and are removed after rules are generated and verification is complete.

## Cleanup policy

GitShred preserves mixed configuration files by default. For `.env`, YAML, JSON, properties, deployment manifests, and connection strings, it creates text replacement rules for confirmed values and keeps the surrounding configuration.

A standalone private key, dedicated token file, or credential file with no non-secret business content may be proposed for deletion. File deletion is exceptional and requires a separate confirmation that restates the exact file patterns and refs and explains the irreversible impact.

Before BFG runs, GitShred checks the current branch and the detected default branch for accepted text rules. If either still contains a confirmed credential, the user must clean it in a normal commit first. BFG is not used to hide a credential that remains in the current version.

The default all-ref scope covers local branches and tags:

```text
refs/heads/*
refs/tags/*
```

Local remote-tracking copies under `refs/remotes/*` are excluded from the default rewrite and push scope. They can be named explicitly in a refs file for audit work, with the limitation that they are local tracking copies rather than normal remote branches.

## Safety boundaries

- History rewriting happens only in a newly created isolated mirror.
- The user's working repository is preserved as a recovery point.
- BFG is never downloaded or installed automatically.
- Candidate discovery and LLM classification are read-only.
- BFG executes only after candidate, scope, mirror, execution, and cleanup confirmations are complete.
- All-ref push guidance uses explicit branch and tag pushes rather than blindly mirroring local remote-tracking refs.
- The mirror's cloned `origin` may point to the local source repository; the real push target must be reviewed explicitly.
- Git history cleanup does not revoke or rotate credentials.
- Remote hidden refs, forks, CI caches, downstream clones, and other copies require separate review.
- The incident is not closed until credential rotation or revocation status is known.

## What the skill reports

The final in-conversation summary records:

- the source and isolated mirror;
- accepted candidates in redacted form;
- the refs scope and excluded refs;
- current and default branch cleanliness;
- BFG and object reclamation results;
- post-cleanup refs and object verification;
- credential rotation or revocation status;
- remote push guidance;
- unresolved refs, downstream copies, or other follow-up work.

GitShred does not automatically push a remote, rotate credentials, synchronize downstream clones, or write a report file unless the user explicitly asks for one.

## Maintainer notes

The bundled Python CLI is an implementation detail used by the skill. Its important internal stages are candidate discovery, accepted-candidate rule export, isolated mirror preparation, BFG planning and execution, object reclamation, verification, and push guidance. The conversational skill is the user-facing interface; users should not need to know these command names to use GitShred.

The skill requires Git and Python 3. BFG must be installed separately when remediation is required. Optional `gitleaks` or `trufflehog` installations may provide additional read-only candidates, but their results still require GitShred review and explicit human approval.
