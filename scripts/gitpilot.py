#!/usr/bin/env python3
"""
gitpilot — a guided, guard-railed git pipeline for check-in, tag, release,
backup and restore.

Design principles (SDLC-architect view):
  1. The safe path is the default path. Every destructive action requires an
     explicit confirmation AND an automatic safety snapshot first.
  2. Sequence is enforced, not remembered. The tool walks you through
     status -> scan -> stage -> commit -> sync -> push -> tag -> release.
  3. Nothing is ever lost. Before restore/reset, gitpilot creates a rescue
     branch + stash + tar snapshot, and tells you how to get back.
  4. Fail loud, fail early. Preflight "doctor" checks run before any flow.

Requires: python3 (stdlib only), git. Optional: gh (GitHub CLI) for releases.
Works on Linux, macOS, Termux/Android, WSL.

Usage:
    python3 gitpilot.py            # interactive menu
    python3 gitpilot.py doctor     # health check only
    python3 gitpilot.py checkin    # guided check-in flow
    python3 gitpilot.py tag        # guided tag flow
    python3 gitpilot.py release    # guided release flow
    python3 gitpilot.py backup     # snapshot working tree + repo bundle
    python3 gitpilot.py restore    # restore a clean tag/commit safely
    python3 gitpilot.py --dry-run <cmd>   # print git commands, don't run them
"""

import os
import re
import sys
import shlex
import shutil
import subprocess
import tarfile
from datetime import datetime, timezone

# ----------------------------- configuration --------------------------------

PROTECTED_BRANCHES = {"main", "master", "release", "production", "prod"}
LARGE_FILE_MB = 25
BACKUP_DIR_NAME = ".gitpilot-backups"

SECRET_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "AWS access key ID"),
    (r"(?i)aws(.{0,20})?(secret|private).{0,20}?[:=]\s*['\"][A-Za-z0-9/+=]{40}['\"]", "AWS secret key"),
    (r"ghp_[A-Za-z0-9]{36}", "GitHub personal access token"),
    (r"github_pat_[A-Za-z0-9_]{22,}", "GitHub fine-grained PAT"),
    (r"gho_[A-Za-z0-9]{36}", "GitHub OAuth token"),
    (r"xox[baprs]-[A-Za-z0-9-]{10,}", "Slack token"),
    (r"sk-[A-Za-z0-9]{20,}", "API secret key (sk- prefix)"),
    (r"-----BEGIN (RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----", "Private key material"),
    (r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{6,}['\"]", "Hard-coded password"),
    (r"(?i)(api[_-]?key|apikey|auth[_-]?token|secret[_-]?key)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]", "Hard-coded API key/token"),
    (r"eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}", "JWT token"),
    (r"mysql://[^\s'\"]+:[^\s'\"]+@", "DB connection string with credentials"),
    (r"postgres(ql)?://[^\s'\"]+:[^\s'\"]+@", "DB connection string with credentials"),
    (r"mongodb(\+srv)?://[^\s'\"]+:[^\s'\"]+@", "DB connection string with credentials"),
]

SKIP_SCAN_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__",
                  "dist", "build", ".tox", ".mypy_cache", BACKUP_DIR_NAME}
SKIP_SCAN_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".pdf", ".zip",
                 ".gz", ".tar", ".whl", ".so", ".dylib", ".dll", ".bin",
                 ".litertlm", ".gguf", ".onnx", ".tflite", ".woff", ".woff2",
                 ".ttf", ".ico", ".mp4", ".mp3", ".sqlite", ".db"}

DRY_RUN = False

# ------------------------------- ui helpers ---------------------------------

class C:
    OK = "\033[92m"; WARN = "\033[93m"; ERR = "\033[91m"
    BOLD = "\033[1m"; DIM = "\033[2m"; CYAN = "\033[96m"; END = "\033[0m"

def use_color() -> bool:
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None

def paint(txt, color):
    return f"{color}{txt}{C.END}" if use_color() else txt

def ok(msg):    print(paint("  ✔ ", C.OK) + msg)
def warn(msg):  print(paint("  ⚠ ", C.WARN) + msg)
def err(msg):   print(paint("  ✘ ", C.ERR) + msg)
def info(msg):  print(paint("  ▸ ", C.CYAN) + msg)
def head(msg):  print("\n" + paint(f"── {msg} ", C.BOLD) + paint("─" * max(0, 60 - len(msg)), C.DIM))

def ask(prompt, default=None):
    suffix = f" [{default}]" if default is not None else ""
    try:
        val = input(paint(f"  ? {prompt}{suffix}: ", C.BOLD)).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(1)
    return val or (default if default is not None else "")

def confirm(prompt, default_no=True):
    d = "y/N" if default_no else "Y/n"
    val = ask(f"{prompt} ({d})").lower()
    if not val:
        return not default_no
    return val in ("y", "yes")

def choose(prompt, options):
    """options: list of (key, label). Returns key or None."""
    print()
    for i, (_, label) in enumerate(options, 1):
        print(f"    {paint(str(i), C.BOLD)}. {label}")
    while True:
        val = ask(prompt + " (number, or q to cancel)")
        if val.lower() in ("q", "quit", ""):
            return None
        if val.isdigit() and 1 <= int(val) <= len(options):
            return options[int(val) - 1][0]
        warn("Invalid choice.")

# ------------------------------ git plumbing --------------------------------

def run(cmd, check=True, capture=True, mutating=False):
    """Run a command. Mutating commands are skipped in dry-run mode."""
    if mutating and DRY_RUN:
        info("[dry-run] " + " ".join(shlex.quote(c) for c in cmd))
        return subprocess.CompletedProcess(cmd, 0, "", "")
    return subprocess.run(cmd, check=check, text=True,
                          capture_output=capture)

def git(*args, check=True, mutating=False):
    return run(["git", *args], check=check, mutating=mutating)

def git_out(*args, default=""):
    try:
        return git(*args).stdout.strip()
    except subprocess.CalledProcessError:
        return default

def in_repo():
    return git_out("rev-parse", "--is-inside-work-tree") == "true"

def repo_root():
    return git_out("rev-parse", "--show-toplevel")

def current_branch():
    br = git_out("rev-parse", "--abbrev-ref", "HEAD")
    if not br:  # unborn branch: repo has no commits yet
        br = git_out("symbolic-ref", "--short", "-q", "HEAD") or "HEAD"
    return br

def has_commits():
    return bool(git_out("rev-parse", "--verify", "-q", "HEAD"))

def has_remote():
    return bool(git_out("remote"))

def default_remote():
    remotes = git_out("remote").splitlines()
    return "origin" if "origin" in remotes else (remotes[0] if remotes else None)

def upstream_of(branch):
    return git_out("rev-parse", "--abbrev-ref", f"{branch}@{{upstream}}", default="")

def dirty_files():
    out = git_out("status", "--porcelain")
    return out.splitlines() if out else []

def repo_in_progress_state():
    gd = git_out("rev-parse", "--git-dir")
    states = []
    for f, label in [("MERGE_HEAD", "merge"), ("REBASE_HEAD", "rebase"),
                     ("CHERRY_PICK_HEAD", "cherry-pick"), ("BISECT_LOG", "bisect")]:
        if os.path.exists(os.path.join(gd, f)):
            states.append(label)
    if os.path.isdir(os.path.join(gd, "rebase-merge")) or \
       os.path.isdir(os.path.join(gd, "rebase-apply")):
        if "rebase" not in states:
            states.append("rebase")
    return states

def timestamp():
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")

# --------------------------------- doctor -----------------------------------

def doctor(verbose=True):
    """Preflight checks. Returns True if safe to proceed with flows."""
    head("Preflight health check")
    healthy = True

    if not shutil.which("git"):
        err("git is not installed or not on PATH."); return False
    ok(f"git found: {git_out('--version')}")

    if not in_repo():
        err("Not inside a git repository. Run this from a project folder "
            "(or `git init` first).")
        return False
    ok(f"Repository root: {repo_root()}")

    name = git_out("config", "user.name")
    email = git_out("config", "user.email")
    if not name or not email:
        warn("git user.name / user.email not set — commits will be rejected "
             "or mis-attributed.")
        if confirm("Set them now?", default_no=False):
            if not name:
                n = ask("Your name")
                if n: git("config", "user.name", n, mutating=True)
            if not email:
                e = ask("Your email")
                if e: git("config", "user.email", e, mutating=True)
        else:
            healthy = False
    else:
        ok(f"Committer identity: {name} <{email}>")

    br = current_branch()
    if br == "HEAD":
        err("You are in DETACHED HEAD state. Commits made here can be lost.")
        info("Fix: git switch -c rescue/<name>   (turns your position into a branch)")
        healthy = False
    else:
        ok(f"Current branch: {br}")
        if br in PROTECTED_BRANCHES:
            warn(f"'{br}' is a protected branch — direct commits are usually "
                 "discouraged. Consider a feature branch.")

    states = repo_in_progress_state()
    if states:
        err(f"Operation in progress: {', '.join(states)}. Finish or abort it "
            f"before using pipelines (e.g. git {states[0]} --continue / --abort).")
        healthy = False

    unmerged = git_out("diff", "--name-only", "--diff-filter=U")
    if unmerged:
        err(f"Unresolved merge conflicts in: {unmerged.replace(chr(10), ', ')}")
        healthy = False

    if has_remote():
        r = default_remote()
        ok(f"Remote configured: {r} → {git_out('remote', 'get-url', r)}")
    else:
        warn("No remote configured. You can commit and tag locally, but not "
             "push or create releases.")

    if not os.path.exists(os.path.join(repo_root(), ".gitignore")):
        warn("No .gitignore found — you risk committing build artifacts, "
             "venvs, and secrets.")

    if shutil.which("gh"):
        ok("GitHub CLI (gh) found — release automation available.")
    else:
        info("GitHub CLI (gh) not found — releases will fall back to "
             "annotated tags + instructions.")

    d = dirty_files()
    if d:
        info(f"{len(d)} file(s) with uncommitted changes.")
    else:
        ok("Working tree is clean.")

    print()
    print(paint("  Overall: ", C.BOLD) +
          (paint("READY", C.OK) if healthy else paint("ISSUES FOUND — fix the ✘ items above", C.ERR)))
    return healthy

# ------------------------------ safety scans --------------------------------

def scan_secrets(paths):
    """Scan given file paths for secret-looking content. Returns findings."""
    findings = []
    root = repo_root()
    for rel in paths:
        p = os.path.join(root, rel)
        if not os.path.isfile(p):
            continue
        if os.path.splitext(p)[1].lower() in SKIP_SCAN_EXT:
            continue
        if any(part in SKIP_SCAN_DIRS for part in rel.split(os.sep)):
            continue
        try:
            if os.path.getsize(p) > 2 * 1024 * 1024:
                continue
            with open(p, "r", encoding="utf-8", errors="ignore") as f:
                for lineno, line in enumerate(f, 1):
                    for pat, label in SECRET_PATTERNS:
                        if re.search(pat, line):
                            findings.append((rel, lineno, label))
        except OSError:
            continue
    return findings

def scan_large(paths):
    root = repo_root()
    big = []
    for rel in paths:
        p = os.path.join(root, rel)
        if os.path.isfile(p):
            mb = os.path.getsize(p) / (1024 * 1024)
            if mb >= LARGE_FILE_MB:
                big.append((rel, mb))
    return big

# ----------------------------- backup / restore -----------------------------

def backup_dir():
    d = os.path.join(repo_root(), BACKUP_DIR_NAME)
    os.makedirs(d, exist_ok=True)
    # keep backups out of git
    ex = os.path.join(git_out("rev-parse", "--git-dir"), "info", "exclude")
    try:
        existing = open(ex).read() if os.path.exists(ex) else ""
        if BACKUP_DIR_NAME not in existing:
            with open(ex, "a") as f:
                f.write(f"\n{BACKUP_DIR_NAME}/\n")
    except OSError:
        pass
    return d

def snapshot_worktree(label="manual"):
    """Tar the working tree (excluding .git and backups). Returns path."""
    ts = timestamp()
    dest = os.path.join(backup_dir(), f"worktree-{label}-{ts}.tar.gz")
    root = repo_root()
    if DRY_RUN:
        info(f"[dry-run] would create snapshot {dest}")
        return dest
    def _filter(ti):
        parts = ti.name.split("/")
        if any(p in (".git", BACKUP_DIR_NAME) for p in parts):
            return None
        return ti
    with tarfile.open(dest, "w:gz") as tar:
        tar.add(root, arcname=os.path.basename(root), filter=_filter)
    ok(f"Working-tree snapshot: {os.path.relpath(dest, root)}")
    return dest

def bundle_repo(label="manual"):
    """git bundle = full portable backup of all refs + history."""
    ts = timestamp()
    dest = os.path.join(backup_dir(), f"repo-{label}-{ts}.bundle")
    git("bundle", "create", dest, "--all", mutating=True)
    ok(f"Full repo bundle (all branches/tags/history): "
       f"{os.path.relpath(dest, repo_root())}")
    info("Restore anywhere with: git clone <bundle-file> <new-dir>")
    return dest

def flow_backup():
    head("Backup")
    print("  Two layers of protection:")
    print("   • worktree snapshot — your files exactly as they are now (incl. uncommitted)")
    print("   • repo bundle       — entire git history, branches and tags in one file")
    snapshot_worktree()
    bundle_repo()
    prune_old_backups()

def prune_old_backups(keep=10):
    d = backup_dir()
    files = sorted(
        (os.path.join(d, f) for f in os.listdir(d)),
        key=os.path.getmtime, reverse=True)
    for old in files[keep:]:
        try:
            os.remove(old)
            info(f"Pruned old backup: {os.path.basename(old)}")
        except OSError:
            pass

def flow_restore():
    head("Restore a clean tag / version")
    print("  gitpilot never throws work away. Before restoring it will:")
    print("   1. snapshot your working tree,  2. stash/park uncommitted changes,")
    print("   3. create a rescue branch at your current position.")

    tags = git_out("tag", "--sort=-creatordate").splitlines()
    target = None
    if tags:
        opts = [(t, f"tag {t}  {paint(git_out('log','-1','--format=%cs %s', t), C.DIM)}")
                for t in tags[:15]]
        opts.append(("__other__", "Enter a commit hash / branch / other ref"))
        target = choose("Restore which version?", opts)
        if target == "__other__":
            target = ask("Ref (tag / commit hash / branch)")
    else:
        info("No tags found in this repository.")
        target = ask("Ref to restore (commit hash / branch)")
    if not target:
        return
    if not git_out("rev-parse", "--verify", f"{target}^{{commit}}"):
        err(f"'{target}' is not a valid ref."); return

    mode = choose("How do you want to restore?", [
        ("inspect", "INSPECT — check out the version on a temporary branch "
                    "(current branch untouched) — safest"),
        ("overlay", "OVERLAY — copy that version's files INTO this folder on "
                    "the current branch (as new uncommitted changes)"),
        ("hard",    "HARD RESET — move this branch to that version "
                    "(destructive to later commits — full backup taken first)"),
    ])
    if mode is None:
        return

    # ---- safety net, always, before anything mutates ----
    snapshot_worktree(label=f"pre-restore-{re.sub(r'[^A-Za-z0-9._-]','_',target)}")
    br = current_branch()
    if dirty_files():
        info("Parking your uncommitted changes in a stash…")
        git("stash", "push", "--include-untracked", "-m",
            f"gitpilot pre-restore {timestamp()}", mutating=True)
        ok("Stashed. Recover any time with: git stash pop")
    if br != "HEAD":
        rescue = f"rescue/{br}-{timestamp()}"
        git("branch", rescue, mutating=True)
        ok(f"Rescue branch created at your current position: {rescue}")

    if mode == "inspect":
        tmp = f"inspect/{re.sub(r'[^A-Za-z0-9._-]','_',target)}-{timestamp()}"
        git("switch", "-c", tmp, target, mutating=True)
        ok(f"Now on branch '{tmp}' at {target}.")
        info(f"Look around; return with: git switch {br}")
    elif mode == "overlay":
        git("checkout", target, "--", ".", mutating=True)
        ok(f"Files from {target} copied into the working tree on '{br}'.")
        info("Nothing is committed yet. Review with `git status` / `git diff --staged`,")
        info("then commit if you want to keep it, or `git restore --staged . && "
             "git checkout -- .` to discard.")
    elif mode == "hard":
        print()
        warn(f"This moves branch '{br}' to {target}. Commits after that point "
             "leave the branch (recoverable via the rescue branch just created).")
        if not confirm(f"Type-confirm: hard reset '{br}' to {target}?"):
            info("Cancelled. Nothing was reset."); return
        bundle_repo(label="pre-hard-reset")
        git("reset", "--hard", target, mutating=True)
        ok(f"'{br}' now points at {target}.")
        info("Undo path: git reset --hard <rescue-branch>  (listed above)")

# ------------------------------ check-in flow -------------------------------

CTYPES = [("feat", "feat — new feature"), ("fix", "fix — bug fix"),
          ("docs", "docs — documentation"), ("refactor", "refactor — no behavior change"),
          ("perf", "perf — performance"), ("test", "test — tests"),
          ("chore", "chore — build/tooling"), ("style", "style — formatting"),
          ("__free__", "Free-form message (no convention)")]

def flow_checkin():
    if not doctor(verbose=False):
        if not confirm("Health check found issues. Continue anyway?"):
            return
    head("Guided check-in")

    d = dirty_files()
    if not d:
        ok("Nothing to commit — working tree is clean.")
        _maybe_push_ahead()
        return

    print(f"  {len(d)} changed file(s):")
    changed_paths = []
    for line in d[:60]:
        status, path = line[:2], line[3:]
        changed_paths.append(path.split(" -> ")[-1].strip('"'))
        print(f"    {paint(status, C.CYAN)} {path}")
    if len(d) > 60:
        info(f"…and {len(d)-60} more")

    # --- protection gates ---
    findings = scan_secrets(changed_paths)
    if findings:
        head("⚠ Possible secrets detected")
        for rel, ln, label in findings[:20]:
            err(f"{rel}:{ln} — {label}")
        warn("Committing secrets to git is near-impossible to fully undo once pushed.")
        if not confirm("Proceed anyway (NOT recommended)?"):
            info("Check-in cancelled. Move secrets to env vars/.env (gitignored) "
                 "and retry."); return

    big = scan_large(changed_paths)
    if big:
        for rel, mb in big:
            warn(f"Large file: {rel} ({mb:.1f} MB) — consider Git LFS or .gitignore.")
        if not confirm("Include large files anyway?"):
            info("Cancelled. Adjust .gitignore or `git lfs track` first."); return

    br = current_branch()
    if br in PROTECTED_BRANCHES:
        warn(f"You are committing directly to protected branch '{br}'.")
        if confirm("Create a feature branch instead?", default_no=False):
            nb = ask("New branch name", f"feature/{timestamp()}")
            git("switch", "-c", nb, mutating=True)
            ok(f"Switched to '{nb}'. Your changes came with you.")

    # --- staging ---
    stage = choose("What should be staged?", [
        ("all", "Everything shown above"),
        ("tracked", "Only already-tracked files (git add -u)"),
        ("pick", "Let me pick file-by-file"),
        ("patch", "Interactive hunks (git add -p — power mode)")])
    if stage is None: return
    if stage == "all":
        git("add", "-A", mutating=True)
    elif stage == "tracked":
        git("add", "-u", mutating=True)
    elif stage == "pick":
        for p in changed_paths:
            if confirm(f"stage {p}?", default_no=False):
                git("add", "--", p, mutating=True)
    elif stage == "patch":
        subprocess.run(["git", "add", "-p"])

    staged = git_out("diff", "--cached", "--name-only")
    if not staged:
        warn("Nothing staged; aborting commit."); return
    ok(f"Staged {len(staged.splitlines())} file(s).")

    # --- commit message (conventional commits helper) ---
    ctype = choose("Commit type?", CTYPES)
    if ctype is None: return
    if ctype == "__free__":
        msg = ask("Commit message")
    else:
        scope = ask("Scope (optional, e.g. 'ui', 'api')", "")
        subject = ask("Short description (imperative: 'add', 'fix', …)")
        msg = f"{ctype}({scope}): {subject}" if scope else f"{ctype}: {subject}"
        body = ask("Longer body (optional, Enter to skip)", "")
        if body:
            msg += "\n\n" + body
    if not msg.strip():
        warn("Empty message; aborting."); return
    git("commit", "-m", msg, mutating=True)
    ok(f"Committed: {msg.splitlines()[0]}")

    _maybe_push_ahead()

def _maybe_push_ahead():
    """Sync with remote safely: fetch, rebase if behind, then push."""
    if not has_remote():
        info("No remote — stopping after local commit."); return
    br = current_branch()
    if br == "HEAD":
        return
    remote = default_remote()
    head("Sync with remote")
    git("fetch", remote, check=False, mutating=True)
    up = upstream_of(br)
    if not up:
        info(f"Branch '{br}' has no upstream yet.")
        if confirm(f"Push and set upstream to {remote}/{br}?", default_no=False):
            git("push", "-u", remote, br, mutating=True)
            ok("Pushed with upstream set.")
        return
    counts = git_out("rev-list", "--left-right", "--count", f"{up}...HEAD")
    behind, ahead = (int(x) for x in counts.split()) if counts else (0, 0)
    if behind:
        warn(f"Your branch is {behind} commit(s) behind {up}.")
        act = choose("How to integrate remote changes?", [
            ("rebase", "Rebase my commits on top (clean history — recommended)"),
            ("merge", "Merge remote into my branch"),
            ("skip", "Skip syncing (push will be rejected)")])
        if act == "rebase":
            r = git("pull", "--rebase", remote, br, check=False, mutating=True)
            if r.returncode != 0:
                err("Rebase hit conflicts. Resolve files, then "
                    "`git rebase --continue` (or `git rebase --abort`), and rerun.")
                return
        elif act == "merge":
            r = git("pull", "--no-rebase", remote, br, check=False, mutating=True)
            if r.returncode != 0:
                err("Merge conflicts. Resolve, commit, and rerun."); return
    if ahead or behind:
        if confirm(f"Push '{br}' to {remote}?", default_no=False):
            r = git("push", remote, br, check=False, mutating=True)
            if r.returncode == 0:
                ok("Pushed.")
            else:
                err("Push failed:\n" + r.stderr.strip())
                info("Never use `git push --force` on shared branches. If you must "
                     "rewrite your own branch: git push --force-with-lease")
    else:
        ok("Branch is up to date with remote.")

# -------------------------------- tag flow ----------------------------------

SEMVER_RE = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)$")

def latest_semver():
    for t in git_out("tag", "--sort=-v:refname").splitlines():
        m = SEMVER_RE.match(t)
        if m:
            return t, tuple(int(x) for x in m.groups())
    return None, None

def flow_tag():
    head("Guided tagging")
    if dirty_files():
        warn("You have uncommitted changes. Tags mark a commit — your "
             "uncommitted work will NOT be part of the tag.")
        if not confirm("Tag the last commit anyway?"):
            info("Run the check-in flow first, then tag."); return

    last_tag, ver = latest_semver()
    if last_tag:
        info(f"Latest version tag: {last_tag}")
        maj, mnr, pat = ver
        prefix = "v" if last_tag.startswith("v") else ""
        options = [
            (f"{prefix}{maj}.{mnr}.{pat+1}", f"PATCH  → {prefix}{maj}.{mnr}.{pat+1}   (bug fixes only)"),
            (f"{prefix}{maj}.{mnr+1}.0",     f"MINOR  → {prefix}{maj}.{mnr+1}.0   (new features, backwards-compatible)"),
            (f"{prefix}{maj+1}.0.0",         f"MAJOR  → {prefix}{maj+1}.0.0   (breaking changes)"),
            ("__custom__", "Custom tag name")]
        new_tag = choose("What kind of release is this?", options)
        if new_tag == "__custom__":
            new_tag = ask("Tag name")
    else:
        info("No semver tags yet.")
        new_tag = ask("Tag name", "v0.1.0")
    if not new_tag:
        return
    if git_out("rev-parse", "--verify", f"refs/tags/{new_tag}", default=""):
        err(f"Tag '{new_tag}' already exists. Tags should be immutable — pick "
            "a new version rather than moving a tag."); return

    # changelog since last tag
    rng = f"{last_tag}..HEAD" if last_tag else "HEAD"
    log = git_out("log", rng, "--format=- %s")
    if log:
        head(f"Changes since {last_tag or 'the beginning'}")
        print("\n".join("   " + l for l in log.splitlines()[:30]))
    msg = ask("Tag message", f"Release {new_tag}")
    annotation = msg + ("\n\n" + log if log else "")
    git("tag", "-a", new_tag, "-m", annotation, mutating=True)
    ok(f"Annotated tag '{new_tag}' created on {git_out('rev-parse','--short','HEAD')}.")

    if has_remote() and confirm(f"Push tag to {default_remote()}?", default_no=False):
        git("push", default_remote(), new_tag, mutating=True)
        ok("Tag pushed.")
    return new_tag, log

# ------------------------------ release flow --------------------------------

def flow_release():
    head("Guided release")
    tags = git_out("tag", "--sort=-creatordate").splitlines()
    tag = None
    if tags and confirm(f"Use existing latest tag '{tags[0]}'?", default_no=False):
        tag = tags[0]
        last, _ = latest_semver()
        log = git_out("log", f"{tags[1]}..{tag}" if len(tags) > 1 else tag,
                      "--format=- %s")
    else:
        res = flow_tag()
        if not res: return
        tag, log = res

    if shutil.which("gh"):
        auth = run(["gh", "auth", "status"], check=False)
        if auth.returncode != 0:
            warn("gh is installed but not authenticated. Run: gh auth login")
            _manual_release_notes(tag); return
        notes = log or f"Release {tag}"
        if confirm(f"Create GitHub release for '{tag}' via gh?", default_no=False):
            r = run(["gh", "release", "create", tag, "--title", tag,
                     "--notes", notes], check=False, mutating=True)
            if r.returncode == 0:
                ok("GitHub release created.")
                if r.stdout.strip(): info(r.stdout.strip())
            else:
                err("gh failed:\n" + r.stderr.strip())
    else:
        _manual_release_notes(tag)

def _manual_release_notes(tag):
    info("Manual release path:")
    print(f"    1. Ensure the tag is pushed:  git push {default_remote() or 'origin'} {tag}")
    print("    2. On GitHub/GitLab: Releases → Draft new release → choose the tag")
    print("    3. Paste the changelog shown above as release notes")

# --------------------------------- history ----------------------------------

# ------------------------------ fix & undo ----------------------------------

def _is_pushed(ref):
    """True if ref exists on any remote (i.e. others may have it)."""
    if not has_remote():
        return False
    r = default_remote()
    git("fetch", r, "--tags", check=False, mutating=True)
    out = git_out("branch", "-r", "--contains", ref, default="")
    if out:
        return True
    # tags: check if the tag exists on the remote
    return bool(git_out("ls-remote", "--tags", r, ref, default=""))

def fix_rename_branch():
    head("Rename a branch")
    branches = git_out("branch", "--format=%(refname:short)").splitlines()
    cur = current_branch()
    opts = [(b, f"{b}{'  (current)' if b == cur else ''}") for b in branches]
    old = choose("Which branch is misnamed?", opts)
    if not old:
        return
    new = ask("New name (e.g. feature/login-fix)")
    if not new:
        return
    if not re.match(r"^[A-Za-z0-9._/-]+$", new) or new.endswith("/") \
       or ".." in new or new.startswith("-"):
        err("That's not a valid branch name."); return
    if new in branches:
        err(f"'{new}' already exists."); return
    if not confirm(f"Rename '{old}' → '{new}'?", default_no=False):
        return

    pushed = has_remote() and bool(
        git_out("ls-remote", "--heads", default_remote(), old, default=""))
    git("branch", "-m", old, new, mutating=True)
    ok(f"Local branch renamed: {old} → {new}")

    if pushed:
        warn(f"'{old}' also exists on {default_remote()}.")
        info("If a Pull/Merge Request is open from the old name, renaming the "
             "remote branch will usually CLOSE it. Check first.")
        if confirm(f"Push '{new}' and delete remote '{old}'?"):
            git("push", "-u", default_remote(), new, mutating=True)
            git("push", default_remote(), "--delete", old, check=False,
                mutating=True)
            ok("Remote updated. Teammates should run: git fetch --prune")
        else:
            info(f"Later, run:  git push -u {default_remote()} {new}  && "
                 f"git push {default_remote()} --delete {old}")
    elif has_remote():
        info(f"When ready: git push -u {default_remote()} {new}")

def fix_rename_tag():
    head("Rename / move a tag")
    print("  Architect's note: tags are treated as IMMUTABLE by git tooling.")
    print("  Renaming an unpushed tag is trivial; renaming a PUSHED tag can")
    print("  break releases and confuse anyone who already fetched it.")
    tags = git_out("tag", "--sort=-creatordate").splitlines()
    if not tags:
        info("No tags in this repo."); return
    old = choose("Which tag?", [(t, t) for t in tags[:20]])
    if not old:
        return
    new = ask("New tag name")
    if not new or new in tags:
        err("Empty or already-existing name."); return

    target = git_out("rev-parse", f"{old}^{{commit}}")
    msg = git_out("tag", "-l", "--format=%(contents)", old) or f"Release {new}"
    pushed = _is_pushed(old)
    if pushed:
        warn(f"Tag '{old}' exists on the remote. If a GitHub/GitLab Release "
             "points at it, that release will lose its tag.")
        if not confirm("Understood — proceed with remote rename too?"):
            return
    git("tag", "-a", new, target, "-m", msg, mutating=True)
    git("tag", "-d", old, mutating=True)
    ok(f"Local: '{old}' → '{new}' (same commit {target[:7]}, message preserved)")
    if pushed and has_remote():
        r = default_remote()
        git("push", r, new, mutating=True)
        git("push", r, f":refs/tags/{old}", mutating=True)
        ok(f"Remote updated on {r}.")
        info("Anyone who fetched the old tag keeps it locally until they run: "
             f"git tag -d {old}")
    elif has_remote():
        info(f"Push when ready: git push {default_remote()} {new}")

def fix_amend_message():
    head("Fix the last commit message")
    if not has_commits():
        info("No commits yet."); return
    last = git_out("log", "-1", "--format=%h %s")
    info(f"Last commit: {last}")
    if _is_pushed("HEAD"):
        warn("This commit is already on the remote. Amending rewrites history —")
        warn("safe ONLY if this is your personal branch and no one pulled it.")
        if not confirm("It's my personal branch, no one else uses it — amend?"):
            info("Safer alternative: make a new commit, or note the correction "
                 "in the PR description.")
            return
    new_msg = ask("New commit message")
    if not new_msg:
        return
    git("commit", "--amend", "-m", new_msg, mutating=True)
    ok("Message amended.")
    if _is_pushed("HEAD~0") and has_remote():
        info(f"Update remote with: git push --force-with-lease "
             f"{default_remote()} {current_branch()}")
        info("(--force-with-lease refuses to overwrite work you haven't seen; "
             "never use plain --force.)")

def fix_add_to_last():
    head("Add forgotten files to the last commit")
    if not has_commits():
        info("No commits yet."); return
    d = dirty_files()
    if not d:
        info("Working tree is clean — nothing to add."); return
    if _is_pushed("HEAD"):
        warn("Last commit is already pushed. Amending it rewrites history.")
        if not confirm("Personal branch only — proceed?"):
            info("Safer: just make a new commit via the check-in flow.")
            return
    for line in d:
        print(f"    {line}")
    if choose("Stage which?", [("all", "All of the above"),
                               ("pick", "Pick file-by-file")]) == "pick":
        for line in d:
            p = line[3:].split(" -> ")[-1].strip('"')
            if confirm(f"stage {p}?", default_no=False):
                git("add", "--", p, mutating=True)
    else:
        git("add", "-A", mutating=True)
    git("commit", "--amend", "--no-edit", mutating=True)
    ok("Files folded into the last commit; message unchanged.")

def fix_undo_last_commit():
    head("Undo the last commit (keep the work)")
    if not has_commits():
        info("No commits yet."); return
    last = git_out("log", "-1", "--format=%h %s")
    info(f"This will remove commit «{last}» from history but leave all its")
    info("changes in your working tree, ready to re-commit differently.")
    if _is_pushed("HEAD"):
        warn("That commit is already pushed — undoing it locally will make "
             "your branch diverge from the remote.")
        act = choose("Better options for a pushed commit:", [
            ("revert", "git revert — new commit that cancels it (safe, recommended)"),
            ("reset",  "Undo locally anyway (I will force-push my personal branch)"),
        ])
        if act == "revert":
            r = git("revert", "--no-edit", "HEAD", check=False, mutating=True)
            if r.returncode == 0:
                ok("Revert commit created. Push normally.")
            else:
                err("Revert conflicted — resolve files then git revert --continue")
            return
        if act is None:
            return
    if not confirm(f"Soft-reset away «{last}»?"):
        return
    git("reset", "--soft", "HEAD~1", mutating=True)
    ok("Commit undone; its changes are staged and waiting. Nothing lost.")

def fix_unstage_or_discard():
    head("Unstage / discard changes")
    act = choose("What do you need?", [
        ("unstage", "Unstage files (keep the edits, just pull them out of "
                    "the next commit)"),
        ("discard", "DISCARD local edits to tracked files (destructive — "
                    "snapshot taken first)"),
    ])
    if act == "unstage":
        staged = git_out("diff", "--cached", "--name-only").splitlines()
        if not staged:
            info("Nothing is staged."); return
        which = choose("Unstage…", [("all", "everything"), ("pick", "pick files")])
        if which == "pick":
            for p in staged:
                if confirm(f"unstage {p}?", default_no=False):
                    git("restore", "--staged", "--", p, mutating=True)
        elif which == "all":
            git("restore", "--staged", ".", mutating=True)
        ok("Done. Edits are still in your files.")
    elif act == "discard":
        d = [l for l in dirty_files() if not l.startswith("??")]
        if not d:
            info("No tracked-file changes to discard."); return
        for line in d:
            print(f"    {line}")
        warn("Discarding cannot be undone by git — that's why a snapshot "
             "comes first.")
        if not confirm("Snapshot, then discard ALL the edits above?"):
            return
        snapshot_worktree(label="pre-discard")
        git("restore", ".", mutating=True)
        ok("Edits discarded. The snapshot in .gitpilot-backups/ has the old state.")

def fix_reflog_rescue():
    head("Recover a lost commit or deleted branch")
    print("  git almost never deletes commits immediately — the reflog keeps")
    print("  ~90 days of everywhere HEAD has been. Find your work below:")
    print()
    log = git_out("reflog", "--date=relative", "-20")
    for line in log.splitlines():
        print("   " + line)
    print()
    sha = ask("Paste the commit id to rescue (Enter to cancel)")
    if not sha:
        return
    if not git_out("rev-parse", "--verify", "-q", f"{sha}^{{commit}}"):
        err("Not a valid commit id."); return
    name = ask("Name for the rescue branch", f"rescue/{sha[:7]}")
    git("branch", name, sha, mutating=True)
    ok(f"Branch '{name}' now points at {sha[:7]}. Your work is safe.")
    info(f"Inspect with: git switch {name}")

def fix_stash_manager():
    head("Stash manager (parked work)")
    st = git_out("stash", "list")
    if not st:
        info("No stashes."); return
    entries = st.splitlines()
    for e in entries:
        print("   " + e)
    idx = ask("Which stash number? (e.g. 0, Enter to cancel)")
    if not idx.isdigit():
        return
    ref = f"stash@{{{idx}}}"
    print()
    print(git_out("stash", "show", "--stat", ref))
    act = choose(f"What to do with {ref}?", [
        ("pop",   "POP — apply it and remove from the stash list"),
        ("apply", "APPLY — apply it but keep it in the list (safer)"),
        ("branch","BRANCH — apply it onto a brand-new branch (zero conflict risk)"),
        ("drop",  "DROP — delete it (snapshot of list shown above)"),
    ])
    if act in ("pop", "apply"):
        r = git("stash", act, ref, check=False, mutating=True)
        ok("Done.") if r.returncode == 0 else err(
            "Conflicts while applying — resolve files; the stash is preserved.")
    elif act == "branch":
        nb = ask("New branch name", f"stash-work-{timestamp()}")
        git("stash", "branch", nb, ref, mutating=True)
        ok(f"Stash applied cleanly on new branch '{nb}'.")
    elif act == "drop":
        if confirm(f"Really delete {ref}?"):
            git("stash", "drop", ref, mutating=True)
            ok("Dropped.")

def flow_fix():
    while True:
        head("🔧 Fix & Undo")
        act = choose("What went wrong?", [
            ("branch",  "I picked a wrong BRANCH name → rename it"),
            ("tag",     "I picked a wrong TAG name → rename/move it"),
            ("msg",     "Last COMMIT MESSAGE is wrong → amend it"),
            ("addlast", "I FORGOT FILES in the last commit → fold them in"),
            ("undo",    "UNDO the last commit but keep the work"),
            ("stagefix","UNSTAGE or DISCARD local changes"),
            ("reflog",  "I LOST a commit / deleted a branch → rescue via reflog"),
            ("stash",   "Manage STASHED (parked) work"),
            ("back",    "Back to main menu")])
        if act in (None, "back"):
            return
        {"branch": fix_rename_branch, "tag": fix_rename_tag,
         "msg": fix_amend_message, "addlast": fix_add_to_last,
         "undo": fix_undo_last_commit, "stagefix": fix_unstage_or_discard,
         "reflog": fix_reflog_rescue, "stash": fix_stash_manager}[act]()

def flow_history():
    head("Recent history")
    print(git_out("log", "--oneline", "--graph", "--decorate", "-15"))
    head("Tags")
    t = git_out("tag", "--sort=-creatordate", "-n1")
    print(t or "  (no tags)")
    st = git_out("stash", "list")
    if st:
        head("Stashes (parked work)")
        print(st)

# ---------------------------------- menu ------------------------------------

def menu():
    while True:
        head("gitpilot — guided git pipeline")
        act = choose("What do you want to do?", [
            ("doctor",  "🩺 Health check (preflight doctor)"),
            ("checkin", "✅ Check in code  (scan → stage → commit → sync → push)"),
            ("tag",     "🏷️  Tag a version (semver-guided, annotated)"),
            ("release", "🚀 Create a release (tag + GitHub release)"),
            ("backup",  "🧰 Backup now (worktree snapshot + full repo bundle)"),
            ("restore", "⏪ Restore a clean tag/version (with safety net)"),
            ("fix",     "🔧 Fix & Undo (rename branch/tag, amend, recover…)"),
            ("history", "📜 Show history / tags / stashes"),
            ("quit",    "Exit")])
        if act in (None, "quit"):
            print("  bye 👋"); return
        FLOWS[act]()

FLOWS = {"doctor": doctor, "checkin": flow_checkin, "tag": flow_tag,
         "release": flow_release, "backup": flow_backup,
         "restore": flow_restore, "fix": flow_fix, "history": flow_history}

def main():
    global DRY_RUN
    args = [a for a in sys.argv[1:]]
    if "--dry-run" in args:
        DRY_RUN = True
        args.remove("--dry-run")
        warn("DRY-RUN mode: mutating git commands will be printed, not executed.")
    if not shutil.which("git"):
        err("git not found on PATH."); sys.exit(1)
    if args and args[0] != "menu":
        cmd = args[0]
        if cmd not in FLOWS:
            err(f"Unknown command '{cmd}'. Options: {', '.join(FLOWS)}"); sys.exit(2)
        if cmd != "doctor" and not in_repo():
            err("Not a git repository."); sys.exit(1)
        FLOWS[cmd]()
    else:
        if not in_repo():
            err("Not a git repository. cd into a project (or git init) first.")
            sys.exit(1)
        menu()

if __name__ == "__main__":
    main()
