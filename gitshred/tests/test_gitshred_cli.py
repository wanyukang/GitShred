import os
import subprocess
import sys
import tempfile
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "scripts" / "gitshred.py"


def run_cmd(args, cwd=None, env=None, check=True):
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    result = subprocess.run(
        args,
        cwd=cwd,
        env=merged_env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"command failed: {args}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


def init_repo(base):
    repo = base / "repo"
    repo.mkdir()
    run_cmd(["git", "init", "-q"], cwd=repo)
    run_cmd(["git", "config", "user.email", "gitshred@example.test"], cwd=repo)
    run_cmd(["git", "config", "user.name", "GitShred Test"], cwd=repo)
    secret = "sk-abcdefghijklmnopqrstuvwxyz987654"
    (repo / "app.env").write_text(f"API_TOKEN={secret}\n", encoding="utf-8")
    run_cmd(["git", "add", "app.env"], cwd=repo)
    run_cmd(["git", "commit", "-q", "-m", "add leaked token"], cwd=repo)
    return repo, secret


def clean_current_version(repo, secret):
    (repo / "app.env").write_text("API_TOKEN=<rotated>\n", encoding="utf-8")
    run_cmd(["git", "add", "app.env"], cwd=repo)
    run_cmd(["git", "commit", "-q", "-m", "remove leaked token"], cwd=repo)


class GitShredCliTests(unittest.TestCase):
    def test_scan_shows_actionable_redacted_matches_without_raw_secret(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            repo, secret = init_repo(base)
            rules = base / "rules.tsv"
            rules.write_text(f"text\tapi-token\t{secret}\n", encoding="utf-8")

            result = run_cmd([sys.executable, str(CLI), "scan", str(repo), str(rules), "--all"])

            self.assertIn("status=matches", result.stdout)
            self.assertIn("rule=api-token", result.stdout)
            self.assertIn("path=app.env", result.stdout)
            self.assertIn("preview=sk-...654", result.stdout)
            self.assertNotIn(secret, result.stdout)
            self.assertNotIn(secret, result.stderr)

    def test_prepare_mirror_creates_isolated_bare_clone(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            repo, _ = init_repo(base)
            mirror = base / "mirror.git"

            result = run_cmd(
                [sys.executable, str(CLI), "prepare-mirror", str(repo), "--destination", str(mirror)]
            )

            self.assertIn("status=ok", result.stdout)
            self.assertIn(f"mirror_path={mirror}", result.stdout)
            bare = run_cmd(["git", "-C", str(mirror), "rev-parse", "--is-bare-repository"])
            self.assertEqual(bare.stdout.strip(), "true")

    def test_run_bfg_requires_explicit_confirmation(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            repo, secret = init_repo(base)
            mirror = base / "mirror.git"
            run_cmd([sys.executable, str(CLI), "prepare-mirror", str(repo), "--destination", str(mirror)])
            rules = base / "rules.tsv"
            rules.write_text(f"text\tapi-token\t{secret}\n", encoding="utf-8")
            fake_bfg = base / "fake-bfg"
            fake_bfg.write_text("#!/usr/bin/env sh\necho fake bfg should not run >> \"$1\"\n", encoding="utf-8")
            fake_bfg.chmod(0o755)

            result = run_cmd(
                [
                    sys.executable,
                    str(CLI),
                    "run-bfg",
                    str(mirror),
                    str(rules),
                    "--all",
                    "--bfg",
                    str(fake_bfg),
                ],
                check=False,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("confirmation_required", result.stderr)

    def test_verify_fails_when_confirmed_rule_is_still_reachable(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            repo, secret = init_repo(base)
            rules = base / "rules.tsv"
            rules.write_text(f"text\tapi-token\t{secret}\n", encoding="utf-8")

            result = run_cmd(
                [sys.executable, str(CLI), "verify", str(repo), str(rules), "--all"],
                check=False,
            )

            self.assertEqual(result.returncode, 1)
            self.assertIn("status=failed", result.stdout)
            self.assertIn("preview=sk-...654", result.stdout)
            self.assertNotIn(secret, result.stdout)

    def test_file_rule_is_reported_without_reading_file_contents(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            repo = base / "repo"
            repo.mkdir()
            run_cmd(["git", "init", "-q"], cwd=repo)
            run_cmd(["git", "config", "user.email", "gitshred@example.test"], cwd=repo)
            run_cmd(["git", "config", "user.name", "GitShred Test"], cwd=repo)
            (repo / ".env.production").write_text("API_TOKEN=hidden\n", encoding="utf-8")
            run_cmd(["git", "add", ".env.production"], cwd=repo)
            run_cmd(["git", "commit", "-q", "-m", "add credential file"], cwd=repo)
            rules = base / "rules.tsv"
            rules.write_text("file\tproduction-env\t.env.production\n", encoding="utf-8")

            result = run_cmd([sys.executable, str(CLI), "scan", str(repo), str(rules), "--all"])

            self.assertIn("status=matches", result.stdout)
            self.assertIn("rule=production-env", result.stdout)
            self.assertIn("path=.env.production", result.stdout)
            self.assertNotIn("hidden", result.stdout)

    def test_confirmed_bfg_is_called_without_exposing_rules(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            repo, secret = init_repo(base)
            clean_current_version(repo, secret)
            mirror = base / "mirror.git"
            run_cmd([sys.executable, str(CLI), "prepare-mirror", str(repo), "--destination", str(mirror)])
            rules = base / "rules.tsv"
            rules.write_text(f"text\tapi-token\t{secret}\n", encoding="utf-8")
            fake_bfg = base / "fake-bfg"
            fake_log = base / "fake-bfg.log"
            fake_bfg.write_text(
                "#!/usr/bin/env sh\nprintf '%s\\n' \"$@\" > \"$GITSHRED_FAKE_LOG\"\n",
                encoding="utf-8",
            )
            fake_bfg.chmod(0o755)

            result = run_cmd(
                [
                    sys.executable,
                    str(CLI),
                    "run-bfg",
                    str(mirror),
                    str(rules),
                    "--all",
                    "--bfg",
                    str(fake_bfg),
                    "--confirm",
                ],
                env={"GITSHRED_FAKE_LOG": str(fake_log)},
            )

            self.assertIn("status=ok", result.stdout)
            self.assertIn("scope=all", result.stdout)
            self.assertTrue(fake_log.exists())
            self.assertIn("--replace-text", fake_log.read_text(encoding="utf-8"))
            self.assertNotIn(secret, fake_log.read_text(encoding="utf-8"))

    def test_run_bfg_blocks_when_current_ref_still_contains_confirmed_rule(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            repo, secret = init_repo(base)
            mirror = base / "mirror.git"
            run_cmd([sys.executable, str(CLI), "prepare-mirror", str(repo), "--destination", str(mirror)])
            rules = base / "rules.tsv"
            rules.write_text(f"text\tapi-token\t{secret}\n", encoding="utf-8")
            fake_bfg = base / "fake-bfg"
            fake_bfg.write_text("#!/usr/bin/env sh\nexit 0\n", encoding="utf-8")
            fake_bfg.chmod(0o755)

            result = run_cmd(
                [
                    sys.executable,
                    str(CLI),
                    "run-bfg",
                    str(mirror),
                    str(rules),
                    "--all",
                    "--bfg",
                    str(fake_bfg),
                    "--confirm",
                ],
                check=False,
            )

            self.assertEqual(result.returncode, 2)
            self.assertIn("current_version_not_clean", result.stderr)

    def test_run_bfg_blocks_when_default_branch_still_contains_confirmed_rule(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            repo, secret = init_repo(base)
            run_cmd(["git", "checkout", "-q", "-b", "clean-branch"], cwd=repo)
            (repo / "app.env").write_text("API_TOKEN=<rotated>\n", encoding="utf-8")
            run_cmd(["git", "add", "app.env"], cwd=repo)
            run_cmd(["git", "commit", "-q", "-m", "clean current branch"], cwd=repo)
            mirror = base / "mirror.git"
            run_cmd([sys.executable, str(CLI), "prepare-mirror", str(repo), "--destination", str(mirror)])
            run_cmd(["git", "--git-dir", str(mirror), "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/master"])
            rules = base / "rules.tsv"
            rules.write_text(f"text\tapi-token\t{secret}\n", encoding="utf-8")
            fake_bfg = base / "fake-bfg"
            fake_bfg.write_text("#!/usr/bin/env sh\nexit 0\n", encoding="utf-8")
            fake_bfg.chmod(0o755)
            result = run_cmd([
                sys.executable, str(CLI), "run-bfg", str(mirror), str(rules), "--all",
                "--bfg", str(fake_bfg), "--confirm"
            ], check=False)
            self.assertEqual(result.returncode, 2)
            self.assertIn("default_branch_not_clean=refs/heads/master", result.stderr)

    def test_run_bfg_honors_refs_file_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            repo, secret = init_repo(base)
            clean_current_version(repo, secret)
            run_cmd(["git", "checkout", "-q", "-b", "maintenance"], cwd=repo)
            (repo / "notes.txt").write_text("maintenance branch\n", encoding="utf-8")
            run_cmd(["git", "add", "notes.txt"], cwd=repo)
            run_cmd(["git", "commit", "-q", "-m", "maintenance branch"], cwd=repo)
            run_cmd(["git", "checkout", "-q", "master"], cwd=repo)
            mirror = base / "mirror.git"
            run_cmd([sys.executable, str(CLI), "prepare-mirror", str(repo), "--destination", str(mirror)])
            rules = base / "rules.tsv"
            rules.write_text(f"text\tapi-token\t{secret}\n", encoding="utf-8")
            refs = base / "refs.txt"
            refs.write_text("refs/heads/master\n", encoding="utf-8")
            fake_bfg = base / "fake-bfg"
            fake_log = base / "fake-bfg.log"
            fake_bfg.write_text(
                "#!/usr/bin/env sh\npwd > \"$GITSHRED_FAKE_LOG\"\nprintf '%s\\n' \"$@\" >> \"$GITSHRED_FAKE_LOG\"\n",
                encoding="utf-8",
            )
            fake_bfg.chmod(0o755)

            result = run_cmd(
                [
                    sys.executable,
                    str(CLI),
                    "run-bfg",
                    str(mirror),
                    str(rules),
                    "--refs-file",
                    str(refs),
                    "--bfg",
                    str(fake_bfg),
                    "--confirm",
                ],
                env={"GITSHRED_FAKE_LOG": str(fake_log)},
            )

            self.assertIn("status=ok", result.stdout)
            self.assertIn("scope=selected", result.stdout)
            self.assertIn("refs_count=1", result.stdout)
            self.assertIn("scoped.git", fake_log.read_text(encoding="utf-8"))

    def test_object_scan_reports_text_rules_with_length_and_preview(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            repo, secret = init_repo(base)
            rules = base / "rules.tsv"
            rules.write_text(f"text\tapi-token\t{secret}\n", encoding="utf-8")

            result = run_cmd([sys.executable, str(CLI), "object-scan", str(repo), str(rules)])

            self.assertIn("status=matches", result.stdout)
            self.assertIn("length=35", result.stdout)
            self.assertIn("preview=sk-...654", result.stdout)
            self.assertNotIn(secret, result.stdout)

    def test_push_guidance_generates_scoped_and_all_ref_commands(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            repo, _ = init_repo(base)
            refs = base / "refs.txt"
            refs.write_text("refs/heads/master\n", encoding="utf-8")

            scoped = run_cmd(
                [
                    sys.executable,
                    str(CLI),
                    "push-guidance",
                    str(repo),
                    "--refs-file",
                    str(refs),
                    "--remote",
                    "origin",
                ]
            )
            all_refs = run_cmd(
                [sys.executable, str(CLI), "push-guidance", str(repo), "--all", "--remote", "origin"]
            )

            self.assertIn("scope=selected", scoped.stdout)
            self.assertIn("git push --force-with-lease origin refs/heads/master:refs/heads/master", scoped.stdout)
            self.assertIn("scope=all", all_refs.stdout)
            self.assertIn("git push --force origin 'refs/heads/*:refs/heads/*'", all_refs.stdout)
            self.assertIn("git push --force origin 'refs/tags/*:refs/tags/*'", all_refs.stdout)
            self.assertNotIn("git push --mirror origin", all_refs.stdout)

    def test_preflight_rejects_password_in_remote_url(self):
        result = run_cmd(
            [
                sys.executable,
                str(CLI),
                "preflight",
                "https://user:password@example.test/repo.git",
            ],
            check=False,
        )

        self.assertEqual(result.returncode, 2)
        self.assertIn("embedded_credentials_in_source", result.stderr)
        self.assertNotIn("password", result.stderr)

    def test_discover_finds_redacted_candidates_without_authorizing_cleanup(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            repo = base / "repo"
            repo.mkdir()
            run_cmd(["git", "init", "-q"], cwd=repo)
            run_cmd(["git", "config", "user.email", "gitshred@example.test"], cwd=repo)
            run_cmd(["git", "config", "user.name", "GitShred Test"], cwd=repo)
            secret = "prod-password-value-123"
            (repo / "deploy.yml").write_text(f"password: {secret}\n", encoding="utf-8")
            run_cmd(["git", "add", "deploy.yml"], cwd=repo)
            run_cmd(["git", "commit", "-q", "-m", "candidate"], cwd=repo)

            result = run_cmd(
                [sys.executable, str(CLI), "discover", str(repo), "--all"]
            )

            self.assertIn("status=candidates", result.stdout)
            self.assertIn('"candidate_id": "C-0001"', result.stdout)
            self.assertIn('"type": "credential-assignment"', result.stdout)
            self.assertIn('"confidence": 0.72', result.stdout)
            self.assertIn('"human_decision": "pending"', result.stdout)
            self.assertNotIn(secret, result.stdout)

    def test_accepted_candidate_exports_restricted_rules_without_printing_secret(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            repo = base / "repo"
            repo.mkdir()
            run_cmd(["git", "init", "-q"], cwd=repo)
            run_cmd(["git", "config", "user.email", "gitshred@example.test"], cwd=repo)
            run_cmd(["git", "config", "user.name", "GitShred Test"], cwd=repo)
            secret = "prod-password-value-123"
            (repo / "deploy.yml").write_text(f"password: {secret}\n", encoding="utf-8")
            run_cmd(["git", "add", "deploy.yml"], cwd=repo)
            run_cmd(["git", "commit", "-q", "-m", "candidate"], cwd=repo)
            store = base / "candidate-store.json"
            store.touch()
            discovered = run_cmd([
                sys.executable, str(CLI), "discover", str(repo), "--all", "--store", str(store)
            ])
            self.assertIn("candidate_store=", discovered.stdout)
            self.assertIn('"occurrences_count": 1', discovered.stdout)
            rules = base / "rules.tsv"
            exported = run_cmd([
                sys.executable, str(CLI), "export-rules", str(store),
                "--accept", "C-0001", "--output", str(rules)
            ])
            self.assertIn("status=rules_created", exported.stdout)
            self.assertEqual(rules.read_text(encoding="utf-8").split("\t", 2)[2].strip(), secret)
            self.assertEqual(rules.stat().st_mode & 0o777, 0o600)
            self.assertNotIn(secret, exported.stdout)

    def test_export_rules_rejects_unknown_candidate(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = Path(tmp) / "store.json"
            store.write_text('{"version": 1, "candidates": []}', encoding="utf-8")
            result = run_cmd([
                sys.executable, str(CLI), "export-rules", str(store),
                "--accept", "C-9999", "--output", str(Path(tmp) / "rules.tsv")
            ], check=False)
            self.assertEqual(result.returncode, 2)
            self.assertIn("unknown_candidate=C-9999", result.stderr)


if __name__ == "__main__":
    unittest.main()
