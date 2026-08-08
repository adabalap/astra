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
    python3 gitpilot.py init       # turn this folder into a git repo (day zero)
    python3 gitpilot.py doctor     # health check only
    python3 gitpilot.py checkin    # guided check-in flow
    python3 gitpilot.py branch     # create / switch / merge / delete branches
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
DEFAULT_BRANCH = "main"

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

# Minimal, widely-useful .gitignore snippets offered at init time.
GITIGNORE_TEMPLATES = {
    "python": """# Python
__pycache__/
*.py[cod]
*.egg-info/
.eggs/
build/
dist/
.venv/
venv/
env/
.mypy_cache/
.pytest_cache/
.coverage
""",
    "node": """# Node
node_modules/
npm-debug.log*
yarn-debug.log*
yarn-error.log*
dist/
build/
.cache/
""",
    "android": """# Android / Gradle
*.apk
*.aab
*.ap_
*.dex
.gradle/
build/
local.properties
.idea/
captures/
*.keystore
*.jks
""",
    "common": """# OS / editor cruft
.DS_Store
Thumbs.db
*.swp
*~
*.log
.idea/
.vscode/

# Secrets / env
.env
.env.*
*.pem
*.key
""",
}

DRY_RUN = False

# ------------------------------- ui helpers ---------------------------------

class C:
    OK = "\033[92m"; WARN = "\033[93m"; ERR = "\033[91m"
    BOLD = "\033[1m"; DIM = "\033[2m"; CYAN = "\033[96m"; END = "\033[0m"

def use_color() -> bool:
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None

def paint(txt, color):
    return f"{color}{txt}{C.END}" if use_color() else txt

def ok(msg):    print(paint("  \u2714 ", C.OK) + msg)
def warn(msg):  print(paint("  \u26a0 ", C.WARN) + msg)
def err(msg):   print(paint("  \u2718 ", C.ERR) + msg)
def info(msg):  print(paint("  \u25b8 ", C.CYAN) + msg)
def head(msg):  print("\n" + paint(f"\u2500\u2500 {msg} ", C.BOLD) + paint("\u2500" * max(0, 60 - len(msg)), C.DIM))

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

def all_branches():
    """Local branch names, current first if possible."""
    out = git_out("branch", "--format=%(refname:short)")
    return out.splitlines() if out else []

def branch_exists(name):
    return bool(git_out("rev-parse", "--verify", "-q", f"refs/heads/{name}", default=""))

def remote_branch_exists(name, remote=None):
    remote = remote or default_remote()
    if not remote:
        return False
    return bool(git_out("ls-remote", "--heads", remote, name, default=""))

def is_protected(name):
    return name in PROTECTED_BRANCHES

def valid_branch_name(name):
    """Validate a branch name. Prefer git's own checker, fall back to regex.

    Returns (ok: bool, reason: str).
    """
    if not name or name != name.strip():
        return False, "name is empty or has surrounding whitespace"
    # Let git be the source of truth when available.
    res = run(["git", "check-ref-format", "--branch", name], check=False)
    if res.returncode == 0:
        return True, ""
    # Fallback heuristics (git not cooperating / very old git).
    if not re.match(r"^[A-Za-z0-9._/-]+$", name):
        return False, "only letters, digits, '.', '_', '/', '-' are allowed"
    if name.startswith("-") or name.startswith("/") or name.endswith("/"):
        return False, "cannot start with '-' or '/', or end with '/'"
    if ".." in name or name.endswith(".lock") or "//" in name:
        return False, "cannot contain '..', '//', or end with '.lock'"
    return True, ""

def ahead_behind(branch, base):
    """Return (ahead, behind) of branch relative to base, or (None, None)."""
    counts = git_out("rev-list", "--left-right", "--count", f"{base}...{branch}")
    if not counts:
        return None, None
    try:
        behind, ahead = (int(x) for x in counts.split())
        return ahead, behind
    except ValueError:
        return None, None

def ensure_identity():
    """Make sure user.name/user.email are set; prompt if missing. Returns bool."""
    name = git_out("config", "user.name")
    email = git_out("config", "user.email")
    if name and email:
        return True
    warn("git user.name / user.email are not set — commits need an author.")
    if not name:
        n = ask("Your name (for commit authorship)")
        if n:
            git("config", "user.name", n, mutating=True)
    if not email:
        e = ask("Your email (for commit authorship)")
        if e:
            git("config", "user.email", e, mutating=True)
    return bool(git_out("config", "user.name") and git_out("config", "user.email"))

# ----------------------- remote / gh helpers --------------------------------

def gh_available():
    return bool(shutil.which("gh"))

def gh_authed():
    if not gh_available():
        return False
    return run(["gh", "auth", "status"], check=False).returncode == 0

def remote_reachable(target):
    """Can we READ from this remote (repo exists AND we have access)?
    `target` is a remote name (e.g. 'origin') or a URL. Uses your normal git
    auth (SSH key / HTTPS token) — nothing to do with `gh`.
    Returns (ok: bool, stderr: str)."""
    if DRY_RUN:
        return True, ""
    r = run(["git", "ls-remote", target], check=False)
    return (r.returncode == 0), (r.stderr or "")

def gh_try_login():
    """Optionally run `gh auth login`. Returns True if authed afterwards.

    Important: this is ONLY needed to auto-CREATE a repo. Pushing/pulling use
    your normal git auth (SSH key or HTTPS token), which is separate from gh.
    """
    if not gh_available():
        return False
    if gh_authed():
        return True
    info("Note: `gh` login is separate from your git SSH/HTTPS auth and is only "
         "needed so gh can CREATE the repo for you. If you already have SSH set "
         "up, you can skip this and just paste a repo URL instead.")
    if not confirm("Log in to GitHub with `gh auth login` now (optional)?",
                   default_no=True):
        return False
    if DRY_RUN:
        info("[dry-run] gh auth login")
        return False
    info("Handing control to `gh` — follow its prompts (Ctrl+C to cancel and "
         "come back to the URL method).")
    try:
        # Interactive: let gh own the terminal (do NOT capture) so prompts show.
        subprocess.run(["gh", "auth", "login"])
    except KeyboardInterrupt:
        print()
        info("gh login cancelled — no problem, we'll use the URL method.")
        return False
    if gh_authed():
        ok("GitHub CLI authenticated.")
        return True
    warn("Still not authenticated with gh — we'll use the URL method instead.")
    return False

def _diagnose_gh_error(stderr):
    """Explain common `gh` API errors, especially token-scope problems."""
    s = (stderr or "").lower()
    if ("not accessible by personal access token" in s
            or "http 403" in s or "resource not accessible" in s
            or "insufficient" in s or "scope" in s):
        warn("Your gh token is missing the required permissions.")
        info("A CLASSIC token needs scopes: 'repo', 'read:org', "
             "'admin:public_key'. A FINE-GRAINED token needs "
             "'Administration: read & write' on your repositories.")
        info("Re-login with:  gh auth login --scopes 'repo,read:org,"
             "admin:public_key'   (or create the repo in the browser instead).")
        return "scope"
    if "already exists" in s:
        info("That repository name already exists on GitHub — reuse it by "
             "pasting its URL below.")
        return "exists"
    return "unknown"

def normalize_remote_url(url):
    """Validate and gently fix common remote-URL mistakes.

    Returns (fixed_url, note). `note` is a human explanation when something was
    changed, or "" if the URL was already fine. Returns (None, reason) if the
    URL is unusable and can't be auto-fixed.

    The classic trap this catches: 'git@github.com/owner/repo.git' (a SLASH
    after the host) which git reads as a bogus local path. The valid SCP-like
    form needs a COLON: 'git@github.com:owner/repo.git'.
    """
    if not url:
        return None, "empty URL"
    u = url.strip()

    # Strip an accidental wrapping in quotes/backticks.
    u = u.strip("'\"`")

    # scp-like SSH: user@host:path  (the correct form)
    m = re.match(r"^([^@/\s]+)@([^:/\s]+):(.+)$", u)
    if m:
        return u, ("" if u == url.strip() else "trimmed surrounding characters")

    # user@host/owner/repo  -> user@host:owner/repo   (slash typo -> colon)
    m = re.match(r"^([^@/\s]+)@([^:/\s]+)/(.+)$", u)
    if m:
        fixed = f"{m.group(1)}@{m.group(2)}:{m.group(3)}"
        return fixed, (f"fixed SSH URL: '{m.group(2)}/' should be "
                       f"'{m.group(2)}:' (host and path are separated by a "
                       "colon, not a slash)")

    # Proper URL schemes are fine as-is.
    if re.match(r"^(https?|ssh|git)://", u):
        return u, ("" if u == url.strip() else "trimmed surrounding characters")

    # Bare 'owner/repo' — assume GitHub over SSH (matches user's existing setup).
    if re.match(r"^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+(\.git)?$", u):
        fixed = f"git@github.com:{u}"
        if not fixed.endswith(".git"):
            fixed += ".git"
        return fixed, f"interpreted '{u}' as GitHub SSH: {fixed}"

    return None, ("unrecognized remote URL. Use one of:\n"
                  "        git@github.com:owner/repo.git   (SSH)\n"
                  "        https://github.com/owner/repo.git   (HTTPS)")

def parse_owner_repo(url):
    """Extract 'owner/name' from an SSH or HTTPS GitHub URL, else ('', '')."""
    if not url:
        return "", ""
    u = url.strip()
    u = re.sub(r"\.git$", "", u)
    # git@github.com:owner/name  OR  ssh://git@github.com/owner/name
    m = re.search(r"[:/]([^/:]+)/([^/]+)$", u)
    if m:
        return m.group(1), m.group(2)
    return "", ""

def diagnose_push_failure(stderr, branch, remote_url=""):
    """Print an accurate, actionable reason for a failed push. Returns a short
    category string: 'not_found' | 'auth' | 'behind' | 'unknown'."""
    s = (stderr or "").lower()
    if ("repository not found" in s or "does not exist" in s
            or "could not read from remote repository" in s):
        info("The remote repository does not exist yet, or your account can't "
             "see it.")
        owner, name = parse_owner_repo(remote_url)
        target = f"{owner}/{name}" if owner and name else "<owner>/<name>"
        if gh_available():
            info(f"Create it and push:  gh repo create {target} --private "
                 "--source=. --push")
            info("(run `gh auth login` first if prompted).")
        else:
            info("Create an EMPTY repo in the web UI (no README), then push "
                 "again.")
        return "not_found"
    if ("permission denied" in s or "publickey" in s
            or "authentication failed" in s or "access denied" in s):
        info("Authentication problem.")
        info("SSH: test with `ssh -T git@github.com` and confirm your key is "
             "added. HTTPS: use a Personal Access Token as the password.")
        return "auth"
    if ("failed to push some refs" in s or "fetch first" in s
            or "non-fast-forward" in s or "rejected" in s):
        info("The remote already has commits your local branch doesn't.")
        info(f"Reconcile:  git pull --rebase origin {branch}   (then push).")
        return "behind"
    info("Check the remote URL and your access, then retry the push.")
    return "unknown"

def _push_set_upstream(remote, branch):
    """Push a branch with -u, diagnosing failure. Returns True on success."""
    r = git("push", "-u", remote, branch, check=False, mutating=True)
    if DRY_RUN or r.returncode == 0:
        ok(f"Pushed '{branch}' and set upstream to {remote}/{branch}.")
        return True
    err("Push failed:\n" + (r.stderr or "").strip())
    url = git_out("remote", "get-url", remote, default="")
    cat = diagnose_push_failure(r.stderr, branch, url)
    # If the repo simply doesn't exist and gh can fix it, offer to do so inline.
    if cat == "not_found" and gh_available():
        if gh_try_login() or gh_authed():
            owner, name = parse_owner_repo(url)
            target = f"{owner}/{name}" if owner and name else ""
            if target and confirm(f"Create '{target}' on GitHub now and push?",
                                  default_no=False):
                vis = choose("Visibility?",
                             [("--private", "Private (recommended)"),
                              ("--public", "Public")]) or "--private"
                # Repo doesn't exist; create it from the existing remote+source.
                cr = run(["gh", "repo", "create", target, vis, "--source=.",
                          "--remote=origin", "--push"], check=False,
                         mutating=True)
                if DRY_RUN or cr.returncode == 0:
                    ok(f"Created '{target}' and pushed.")
                    return True
                # gh may object that 'origin' already exists; fall back to a
                # plain create + push.
                cr2 = run(["gh", "repo", "create", target, vis],
                          check=False, mutating=True)
                if DRY_RUN or cr2.returncode == 0:
                    r2 = git("push", "-u", remote, branch, check=False,
                             mutating=True)
                    if DRY_RUN or r2.returncode == 0:
                        ok(f"Created '{target}' and pushed '{branch}'.")
                        return True
                    err("Push still failed:\n" + (r2.stderr or "").strip())
                else:
                    err("gh repo create failed:\n" + (cr2.stderr or "").strip())
    return False

# ---------------------------------- init ------------------------------------

def flow_init():
    """Turn the current directory into a git repo, establish `main`, make the
    first commit, optionally wire up a remote, and drop into the feature-branch
    workflow. The 'day zero' onboarding for an existing folder.
    """
    head("Initialize a repository from this folder")
    cwd = os.getcwd()
    info(f"Target folder: {cwd}")

    # 0) already a repo? Don't clobber.
    if in_repo():
        root = repo_root()
        if os.path.abspath(root) == os.path.abspath(cwd):
            warn("This folder is ALREADY a git repository.")
        else:
            warn(f"This folder is inside an existing repository at: {root}")
        info("Nothing to initialize. Use `checkin` to commit, or `branch` to "
             "start a feature branch.")
        return

    entries = [e for e in os.listdir(cwd) if e not in (".", "..")]
    if not entries:
        info("Folder is empty — that's fine, we'll create the repo scaffolding.")
    else:
        info(f"Found {len(entries)} item(s) to bring under version control.")

    if not confirm(f"Create a new git repo here and set '{DEFAULT_BRANCH}' as "
                   "the default branch?", default_no=False):
        info("Cancelled — no repository created."); return

    # 1) git init with main as the initial branch (portable across git versions)
    res = run(["git", "init", "-b", DEFAULT_BRANCH], check=False, mutating=True)
    if res.returncode != 0:
        # older git without -b: init then rename the unborn branch
        git("init", mutating=True)
        run(["git", "symbolic-ref", "HEAD", f"refs/heads/{DEFAULT_BRANCH}"],
            check=False, mutating=True)
    if not DRY_RUN and not in_repo():
        err("git init did not produce a repository. Aborting."); return
    ok(f"Initialized empty repository (default branch: {DEFAULT_BRANCH}).")

    # 2) committer identity
    if not DRY_RUN and not ensure_identity():
        warn("No author identity set; you can add it later via `doctor`. "
             "Continuing, but the first commit may fail.")

    # 3) .gitignore — strongly recommended before the first add
    root = cwd if DRY_RUN else repo_root()
    gi_path = os.path.join(root, ".gitignore")
    if os.path.exists(gi_path):
        info(".gitignore already present — leaving it as-is.")
    else:
        if confirm("Create a .gitignore now (recommended, keeps junk/secrets "
                   "out)?", default_no=False):
            picks = choose("Which starter set?", [
                ("python",  "Python"),
                ("node",    "Node / JavaScript"),
                ("android", "Android / Gradle"),
                ("common",  "Just OS/editor + secrets basics"),
                ("__skip__", "Skip for now"),
            ])
            if picks and picks != "__skip__":
                content = GITIGNORE_TEMPLATES.get(picks, "")
                # always fold in the common OS/secret rules
                if picks != "common":
                    content = content + "\n" + GITIGNORE_TEMPLATES["common"]
                if DRY_RUN:
                    info(f"[dry-run] would write .gitignore ({picks} + common)")
                else:
                    with open(gi_path, "w") as f:
                        f.write(content)
                    ok("Wrote .gitignore.")

    # 4) preflight the very first commit: secret + large-file scan
    #    We scan what WOULD be tracked (respecting .gitignore) before staging.
    if not DRY_RUN:
        would_track = git_out("add", "-A", "--dry-run", default="")
        candidate = []
        for line in would_track.splitlines():
            # lines look like: add 'path/to/file'
            m = re.match(r"add '(.+)'$", line.strip())
            if m:
                candidate.append(m.group(1))
        if candidate:
            findings = scan_secrets(candidate)
            if findings:
                head("\u26a0 Possible secrets detected in the initial import")
                for rel, ln, label in findings[:20]:
                    err(f"{rel}:{ln} — {label}")
                warn("Once these land in the first commit they are in history "
                     "forever. Move them to .env / env vars and .gitignore them.")
                if not confirm("Commit them into history anyway (NOT "
                               "recommended)?"):
                    info("Init paused. Nothing committed. Clean up secrets, then "
                         "re-run `gitpilot init`.")
                    return
            big = scan_large(candidate)
            if big:
                for rel, mb in big:
                    warn(f"Large file: {rel} ({mb:.1f} MB) — consider Git LFS or "
                         ".gitignore before the first commit.")
                if not confirm("Include large files in the first commit?"):
                    info("Init paused. Adjust .gitignore / `git lfs track`, then "
                         "re-run `gitpilot init`.")
                    return

    # 5) stage + first commit on main
    git("add", "-A", mutating=True)
    staged = git_out("diff", "--cached", "--name-only")
    if not staged and not DRY_RUN:
        info("Nothing to commit yet (empty folder or everything ignored).")
        info("Add some files, then run `gitpilot checkin`.")
    else:
        n = len(staged.splitlines()) if staged else 0
        msg = ask("First commit message", "chore: initial commit")
        if not msg.strip():
            msg = "chore: initial commit"
        r = git("commit", "-m", msg, check=False, mutating=True)
        if not DRY_RUN and r.returncode != 0:
            err("First commit failed:\n" + (r.stderr or "").strip())
            info("Fix the issue (often a missing identity) and re-run `init`.")
            return
        ok(f"Committed {n} file(s) on '{DEFAULT_BRANCH}': {msg}")

    # 6) optional remote wiring
    remote_ready = _init_wire_remote()

    # 7) hand off into the workflow: start a feature branch?
    if has_commits() or DRY_RUN:
        print()
        if confirm("Start your first feature branch now (keep 'main' clean)?",
                   default_no=False):
            branch_new(offer_publish=remote_ready)
        else:
            info("You're on 'main'. When ready: `gitpilot branch` to create a "
                 "feature branch, or `gitpilot checkin` to commit more.")

def _set_origin(url):
    """Add 'origin' or repoint it if it already exists."""
    if "origin" in git_out("remote", default="").splitlines():
        git("remote", "set-url", "origin", url, mutating=True)
    else:
        git("remote", "add", "origin", url, mutating=True)

def _init_wire_remote():
    """Attach an origin remote and push main. Returns True if a remote is now
    usable (successfully pushed), False otherwise."""
    if has_remote():
        info(f"Remote already configured: {default_remote()}.")
        return remote_branch_exists(DEFAULT_BRANCH)
    if not confirm("Connect this repo to a remote (GitHub/GitLab) now?",
                   default_no=False):
        info("No remote yet. Later: git remote add origin <url> && "
             f"git push -u origin {DEFAULT_BRANCH}")
        return False
    return _setup_remote_interactive()

def _setup_remote_interactive():
    """Shared remote setup used by `init` and the standalone `remote` command.
    Leads with the URL/SSH path (which uses your EXISTING git auth); `gh` is
    offered only as an optional convenience to auto-create the repo.
    Returns True if main was pushed successfully."""
    info("How auth works here: pushing uses your normal git credentials "
         "(SSH key or HTTPS token) — the same ones that already work from the "
         "shell. The GitHub CLI (`gh`) is OPTIONAL and only used to auto-CREATE "
         "the repository.")
    method = choose("How do you want to set up the remote?", [
        ("url", "I have the repo URL (or will create it in the browser) — paste "
                "it and push   [uses your existing SSH/HTTPS auth]"),
        ("gh",  "Let `gh` create the GitHub repo for me   [needs a one-time gh "
                "login]"),
        ("skip", "Skip for now"),
    ])
    if method in (None, "skip"):
        info("Skipped. Later: git remote add origin <url> && "
             f"git push -u origin {DEFAULT_BRANCH}")
        return False
    if method == "gh":
        if gh_available() and (gh_authed() or gh_try_login()):
            return _gh_create_and_push()
        warn("Couldn't use `gh` (not installed or not logged in). Falling back "
             "to the URL method, which only needs your existing git auth.")
    return _remote_via_url()

def _gh_create_and_push():
    """Create the repo via gh from the current folder. Returns True on push."""
    default_name = os.path.basename(os.getcwd())
    name = ask("Repository name (owner/name or just name)", default_name)
    vis = choose("Visibility?", [("--private", "Private (recommended)"),
                                 ("--public", "Public")]) or "--private"
    cmd = ["gh", "repo", "create", name, vis, "--source=.",
           "--remote=origin", "--push"]
    r = run(cmd, check=False, mutating=True)
    if DRY_RUN or r.returncode == 0:
        ok(f"Created GitHub repo '{name}', set origin, pushed "
           f"'{DEFAULT_BRANCH}'.")
        if not DRY_RUN and r.stdout.strip():
            info(r.stdout.strip())
        return True
    err("gh repo create failed:\n" + (r.stderr or "").strip())
    _diagnose_gh_error(r.stderr)
    info("You can still add a remote manually (your SSH key already works).")
    return _remote_via_url()

def _remote_via_url():
    """Add an origin URL, verify reachability, then push. Uses existing git
    auth (SSH/HTTPS). Returns True if push succeeded."""
    print("  If the repo doesn't exist yet, create an EMPTY one in the web UI")
    print("  (no README/license, so histories don't clash), then paste its URL.")
    url = ask("Remote URL (git@github.com:you/repo.git or https://…), Enter to "
              "skip")
    if not url:
        info("Skipped. Later: git remote add origin <url> && "
             f"git push -u origin {DEFAULT_BRANCH}")
        return False
    fixed, note = normalize_remote_url(url)
    if fixed is None:
        err(f"That URL won't work: {note}")
        return False
    if note:
        warn(note)
        if not confirm(f"Use '{fixed}'?", default_no=False):
            info("Cancelled. Re-run remote setup with a corrected URL.")
            return False
    url = fixed
    _set_origin(url)
    ok(f"origin \u2192 {url}")

    # Verify we can actually read the remote BEFORE trying to push, so we can
    # give a precise reason instead of a raw push error.
    reachable, errtext = remote_reachable("origin")
    if not reachable:
        err("Can't read from that remote yet (checked with `git ls-remote`).")
        cat = diagnose_push_failure(errtext, DEFAULT_BRANCH, url)
        if cat == "not_found":
            owner, name = parse_owner_repo(url)
            target = f"{owner}/{name}" if owner and name else ""
            # Offer gh create only if it's genuinely available+authed.
            if target and gh_available() and (gh_authed() or gh_try_login()):
                if confirm(f"Create '{target}' on GitHub now with gh and push?",
                           default_no=False):
                    vis = choose("Visibility?",
                                 [("--private", "Private (recommended)"),
                                  ("--public", "Public")]) or "--private"
                    cr = run(["gh", "repo", "create", target, vis],
                             check=False, mutating=True)
                    if DRY_RUN or cr.returncode == 0:
                        return _push_set_upstream("origin", DEFAULT_BRANCH)
                    err("gh repo create failed:\n" + (cr.stderr or "").strip())
                    return False
            # No gh path — let them create it in the browser and retry.
            if confirm("Create the empty repo in your browser now, then retry?",
                       default_no=False):
                ask("Press Enter once the empty repo exists on the web")
                reachable, errtext = remote_reachable("origin")
                if not reachable:
                    err("Still can't read the remote.")
                    diagnose_push_failure(errtext, DEFAULT_BRANCH, url)
                    info(f"When it's ready: git push -u origin {DEFAULT_BRANCH}")
                    return False
            else:
                info(f"When it's ready: git push -u origin {DEFAULT_BRANCH}")
                return False
        else:
            info(f"Once resolved: git push -u origin {DEFAULT_BRANCH}")
            return False

    # Reachable — safe to push.
    if confirm(f"Push '{DEFAULT_BRANCH}' and set upstream now?",
               default_no=False):
        return _push_set_upstream("origin", DEFAULT_BRANCH)
    info(f"Later: git push -u origin {DEFAULT_BRANCH}")
    return False

def flow_remote():
    """Standalone remote manager: set up, verify, re-point, or push."""
    head("Remote")
    if not has_remote():
        info("No remote configured yet.")
        _setup_remote_interactive()
        return
    r = default_remote()
    url = git_out("remote", "get-url", r, default="")
    info(f"Current remote: {r} \u2192 {url}")
    reachable, errtext = remote_reachable(r)
    if reachable:
        ok("Reachable — the repo exists and your git auth works.")
    else:
        err("Not reachable with your current git auth.")
        diagnose_push_failure(errtext, current_branch(), url)
    act = choose("What do you want to do?", [
        ("verify",  "Re-check connectivity"),
        ("repoint", "Change the remote URL"),
        ("push",    f"Push '{current_branch()}' (set upstream)"),
        ("create",  "Create the GitHub repo with gh (if it doesn't exist)"),
        ("back",    "Back"),
    ])
    if act in (None, "back"):
        return
    if act == "verify":
        okr, e = remote_reachable(r)
        ok("Reachable.") if okr else diagnose_push_failure(e, current_branch(), url)
    elif act == "repoint":
        new = ask("New remote URL")
        if new:
            fixed, note = normalize_remote_url(new)
            if fixed is None:
                err(f"That URL won't work: {note}"); return
            if note:
                warn(note)
                if not confirm(f"Use '{fixed}'?", default_no=False):
                    return
            new = fixed
            _set_origin(new); ok(f"origin \u2192 {new}")
            okr, e = remote_reachable("origin")
            ok("Reachable.") if okr else diagnose_push_failure(e, current_branch(), new)
    elif act == "push":
        _push_set_upstream(r, current_branch())
    elif act == "create":
        if gh_available() and (gh_authed() or gh_try_login()):
            owner, name = parse_owner_repo(url)
            target = f"{owner}/{name}" if owner and name else \
                ask("Repository (owner/name)")
            if target:
                vis = choose("Visibility?",
                             [("--private", "Private (recommended)"),
                              ("--public", "Public")]) or "--private"
                cr = run(["gh", "repo", "create", target, vis],
                         check=False, mutating=True)
                if DRY_RUN or cr.returncode == 0:
                    ok(f"Created '{target}'.")
                    if confirm(f"Push '{current_branch()}' now?", default_no=False):
                        _push_set_upstream(r, current_branch())
                else:
                    err("gh repo create failed:\n" + (cr.stderr or "").strip())
        else:
            info("gh unavailable — create the empty repo in the browser, then "
                 "use 'Push' here.")

# --------------------------------- doctor -----------------------------------

def doctor(verbose=True):
    """Preflight checks. Returns True if safe to proceed with flows."""
    head("Preflight health check")
    healthy = True

    if not shutil.which("git"):
        err("git is not installed or not on PATH."); return False
    ok(f"git found: {git_out('--version')}")

    if not in_repo():
        err("Not inside a git repository. Run `gitpilot init` to create one "
            "from this folder.")
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
        ok(f"Remote configured: {r} \u2192 {git_out('remote', 'get-url', r)}")
    else:
        warn("No remote configured. You can commit and tag locally, but not "
             "push or create releases.")

    if not os.path.exists(os.path.join(repo_root(), ".gitignore")):
        warn("No .gitignore found — you risk committing build artifacts, "
             "venvs, and secrets.")

    # Connectivity uses your git auth (SSH/HTTPS); gh is a separate, optional
    # tool only for creating repos/releases. Report them independently.
    if has_remote():
        reachable, _ = remote_reachable(default_remote())
        if reachable:
            ok("Remote reachable with your git auth (SSH/HTTPS).")
        else:
            warn("Remote configured but NOT reachable — the repo may not exist "
                 "yet, or your SSH key/token isn't set up for it.")
    if gh_available():
        ok("GitHub CLI (gh) found — optional; used for repo/release creation." +
           ("" if gh_authed() else "  (not logged in — not required for push)"))
    else:
        info("GitHub CLI (gh) not found — optional. Push/pull still work over "
             "SSH/HTTPS; releases fall back to annotated tags + instructions.")

    d = dirty_files()
    if d:
        info(f"{len(d)} file(s) with uncommitted changes.")
    else:
        ok("Working tree is clean.")

    print()
    print(paint("  Overall: ", C.BOLD) +
          (paint("READY", C.OK) if healthy else paint("ISSUES FOUND — fix the \u2718 items above", C.ERR)))
    return healthy

# ------------------------------ safety scans --------------------------------

def scan_secrets(paths):
    """Scan given file paths for secret-looking content. Returns findings."""
    findings = []
    root = repo_root() or os.getcwd()
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
    root = repo_root() or os.getcwd()
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
    print("   \u2022 worktree snapshot — your files exactly as they are now (incl. uncommitted)")
    print("   \u2022 repo bundle       — entire git history, branches and tags in one file")
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
        head("\u26a0 Possible secrets detected")
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
            _push_set_upstream(remote, br)
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
                err("Push failed:\n" + (r.stderr or "").strip())
                diagnose_push_failure(r.stderr, br,
                                      git_out("remote", "get-url", remote, default=""))
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
            (f"{prefix}{maj}.{mnr}.{pat+1}", f"PATCH  \u2192 {prefix}{maj}.{mnr}.{pat+1}   (bug fixes only)"),
            (f"{prefix}{maj}.{mnr+1}.0",     f"MINOR  \u2192 {prefix}{maj}.{mnr+1}.0   (new features, backwards-compatible)"),
            (f"{prefix}{maj+1}.0.0",         f"MAJOR  \u2192 {prefix}{maj+1}.0.0   (breaking changes)"),
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

    if gh_available():
        if not gh_authed():
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

# ------------------------------ branch flow ---------------------------------

BRANCH_PREFIXES = [
    ("feature/", "feature/  — new functionality"),
    ("fix/",     "fix/      — bug fix"),
    ("hotfix/",  "hotfix/   — urgent production fix"),
    ("chore/",   "chore/    — tooling / maintenance"),
    ("release/", "release/  — release stabilization"),
    ("__none__", "(no prefix — type the full name myself)"),
]

def ref_exists(ref):
    """True if `ref` resolves to a commit locally."""
    if not ref:
        return False
    return bool(git_out("rev-parse", "--verify", "-q", f"{ref}^{{commit}}",
                        default=""))

def remote_default_branch(remote):
    """Return the remote's default branch ref (e.g. 'origin/main') if we can
    resolve it locally, else ''. Tries origin/HEAD, and falls back to a remote
    tracking branch matching a common default name."""
    if not remote:
        return ""
    # origin/HEAD is only present after a clone or `git remote set-head`.
    head = git_out("symbolic-ref", "-q", "--short", f"refs/remotes/{remote}/HEAD",
                   default="")
    if head and ref_exists(head):
        return head
    for b in ("main", "master", "develop"):
        cand = f"{remote}/{b}"
        if ref_exists(cand):
            return cand
    return ""

def _pick_base_ref():
    """Let the user choose the base to branch/merge from. Returns ref or None.

    Only offers refs that ACTUALLY resolve, so we never present a dead option
    like 'origin/HEAD' on an init'd (non-cloned) repo where it was never set."""
    remote = default_remote()
    locals_ = all_branches()
    opts = []
    # Prefer an up-to-date main/master base at the top.
    for b in ("main", "master", "develop"):
        if b in locals_:
            opts.append((b, f"{b}  (local)"))
    for b in locals_:
        if b not in ("main", "master", "develop"):
            opts.append((b, f"{b}  (local)"))
    # Only surface the remote default if it genuinely resolves locally.
    rdef = remote_default_branch(remote)
    if rdef:
        opts.append((rdef, f"{rdef}  (remote default branch)"))
    opts.append(("__other__", "Other ref (tag / commit / remote branch)"))
    while True:
        base = choose("Base this off which ref?", opts)
        if base is None:
            return None
        if base == "__other__":
            base = ask("Ref (e.g. origin/main, a tag, or a commit)")
            if not base:
                return None
        # Validate here so a bad pick re-prompts instead of aborting the flow.
        if ref_exists(base):
            return base
        err(f"'{base}' is not a valid ref. Pick another.")

def branch_new(offer_publish=True):
    head("Create a new branch")
    # 1) choose base (already validated to resolve inside _pick_base_ref)
    base = _pick_base_ref()
    if not base:
        return

    # 2) offer to refresh the base from the remote first (best practice).
    #    Only meaningful if the remote actually has this branch.
    remote = default_remote()
    if remote and "/" not in base and remote_branch_exists(base) and confirm(
            f"Fetch latest '{base}' from {remote} first (recommended)?",
            default_no=False):
        git("fetch", remote, base, check=False, mutating=True)
        up = upstream_of(base)
        if up:
            a, b = ahead_behind(base, up)
            if b:
                warn(f"Local '{base}' is {b} commit(s) behind {up}. "
                     f"Branching from {up} instead to start fresh.")
                base = up

    # 3) name it (prefix helper -> conventional branch names)
    prefix = choose("Branch type?", BRANCH_PREFIXES)
    if prefix is None:
        return
    if prefix == "__none__":
        name = ask("Full branch name")
    else:
        slug = ask(f"Short description after '{prefix}' (e.g. login-timeout)")
        slug = re.sub(r"\s+", "-", slug.strip().lower())
        slug = re.sub(r"[^a-z0-9._/-]", "", slug)
        name = f"{prefix}{slug}" if slug else ""
    if not name:
        warn("No branch name given; cancelled."); return
    valid, reason = valid_branch_name(name)
    if not valid:
        err(f"Invalid branch name ({reason})."); return
    if branch_exists(name):
        err(f"Branch '{name}' already exists."); return

    # 4) carry uncommitted work? git switch -c brings changes along by default.
    if dirty_files():
        info("You have uncommitted changes; they will move to the new branch "
             "with you (git's default).")

    git("switch", "-c", name, base, mutating=True)
    ok(f"Created and switched to '{name}' (based on {base}).")

    # 5) publish — but only if the remote is actually usable. If main was never
    #    pushed (e.g. remote repo doesn't exist yet), don't repeat that failure.
    if not remote:
        info(f"No remote yet. When ready: git push -u origin {name}")
        return
    if not offer_publish and not remote_branch_exists(DEFAULT_BRANCH):
        info("Remote isn't set up yet (main hasn't been pushed). Skipping publish.")
        info(f"Once the remote exists: git push -u {remote} {name}")
        return
    if confirm(f"Publish '{name}' to {remote} and set upstream?",
               default_no=False):
        _push_set_upstream(remote, name)
    else:
        info(f"When ready to publish: git push -u {remote} {name}")

def branch_switch():
    head("Switch branch")
    branches = all_branches()
    cur = current_branch()
    if not branches:
        info("No local branches."); return
    opts = [(b, f"{b}{'  (current)' if b == cur else ''}") for b in branches
            if b != cur]
    opts.append(("__new__", "+ create a new branch instead"))
    target = choose("Switch to…", opts)
    if target is None:
        return
    if target == "__new__":
        return branch_new()
    if dirty_files():
        warn("You have uncommitted changes.")
        act = choose("Before switching…", [
            ("carry", "Carry them with me (git switch — fails on conflict)"),
            ("stash", "Stash them here, switch clean, I'll pop later"),
            ("cancel", "Cancel")])
        if act == "cancel" or act is None:
            return
        if act == "stash":
            git("stash", "push", "--include-untracked", "-m",
                f"gitpilot pre-switch {timestamp()}", mutating=True)
            ok("Stashed. After switching: git stash pop")
    r = git("switch", target, check=False, mutating=True)
    if r.returncode == 0:
        ok(f"On branch '{target}'.")
    else:
        err("Switch failed:\n" + (r.stderr or "").strip())
        info("Tip: commit or stash your changes, then try again.")

def _do_merge(source, target):
    """Merge `source` INTO `target`. Assumes we are standing on `target` and
    the working tree is clean. Handles style choice, snapshot, conflicts, push.
    """
    # Show what would come in.
    a, b = ahead_behind(source, target)
    if a == 0:
        ok(f"'{source}' has nothing '{target}' doesn't already have — "
           "already merged.")
        return
    if a is not None:
        info(f"'{source}' has {a} commit(s) not yet in '{target}':")
        log = git_out("log", f"{target}..{source}", "--format=- %s", default="")
        print("\n".join("     " + l for l in log.splitlines()[:20]) or "     (none)")

    strategy = choose("Merge style?", [
        ("noff", "Merge commit ALWAYS (--no-ff) — keeps a clear merge point "
                 "(recommended for feature branches)"),
        ("ff",   "Fast-forward if possible (--ff) — linear history when it can"),
        ("squash", "Squash — combine all of the branch's commits into ONE, "
                   "which you then commit"),
    ])
    if strategy is None:
        return

    # Safety net before touching the branch.
    snapshot_worktree(label=f"pre-merge-{re.sub(r'[^A-Za-z0-9._-]','_',source)}")

    if strategy == "squash":
        r = git("merge", "--squash", source, check=False, mutating=True)
        if r.returncode != 0:
            err("Squash merge hit conflicts. Resolve files, `git add` them, "
                "then commit. To bail out: git merge --abort")
            return
        ok("Squash staged. All of the branch's changes are staged as one.")
        msg = ask("Commit message for the squashed merge",
                  f"merge {source} into {target} (squash)")
        if msg.strip():
            git("commit", "-m", msg, mutating=True)
            ok("Squashed merge committed.")
        else:
            info("Nothing committed yet; run the check-in flow when ready.")
    else:
        flag = "--no-ff" if strategy == "noff" else "--ff"
        r = git("merge", flag, "--no-edit", source, check=False, mutating=True)
        if r.returncode != 0:
            err("Merge produced conflicts.")
            unmerged = git_out("diff", "--name-only", "--diff-filter=U")
            if unmerged:
                for f in unmerged.splitlines():
                    warn(f"  conflict: {f}")
            info("Resolve each file, `git add` it, then `git commit` to finish.")
            info("Or keep one whole side:  git checkout --theirs <file>  "
                 "(the branch coming in)  /  --ours <file>  (this branch).")
            info("Changed your mind? `git merge --abort` restores the pre-merge state.")
            return
        ok(f"Merged '{source}' into '{target}'.")

    if has_remote() and confirm(f"Push '{target}' to {default_remote()}?",
                                default_no=False):
        remote = default_remote()
        r = git("push", remote, target, check=False, mutating=True)
        if r.returncode == 0:
            ok("Pushed.")
        else:
            err("Push failed:\n" + (r.stderr or "").strip())
            diagnose_push_failure(r.stderr, target,
                                  git_out("remote", "get-url", remote, default=""))

def _ensure_clean_tree(context="merge"):
    """Return True if safe to proceed (clean tree, or stashed on request)."""
    if not dirty_files():
        return True
    warn("Working tree has uncommitted changes. Commit or stash them first so "
         f"a conflicting {context} can be aborted cleanly.")
    if confirm("Stash them now and continue?", default_no=False):
        git("stash", "push", "--include-untracked", "-m",
            f"gitpilot pre-{context} {timestamp()}", mutating=True)
        ok("Stashed. Recover later with: git stash pop")
        return True
    info("Cancelled.")
    return False

def branch_merge():
    head("Merge a branch")
    branches = all_branches()
    cur = current_branch()
    if cur == "HEAD":
        err("Detached HEAD — switch to a branch before merging."); return
    if len(branches) < 2:
        info("Need at least two branches to merge."); return

    # Direction chooser — so you don't have to already be standing on the
    # destination. This is the common "get my feature onto main" case.
    direction = choose("Which way should the merge go?", [
        ("into_cur", f"Bring another branch INTO '{cur}'  (stay on '{cur}')"),
        ("cur_into", f"Send '{cur}' INTO another branch  (I'll switch there first)"),
    ])
    if direction is None:
        return

    if direction == "cur_into":
        # Merge the current branch into a chosen target (typically main).
        source = cur
        opts = [(b, b + ("   [protected]" if is_protected(b) else "")) for b in branches if b != cur]
        opts.append(("__other__", "Other target (local branch)"))
        target = choose(f"Send '{cur}' INTO which branch?", opts)
        if target is None:
            return
        if target == "__other__":
            target = ask("Target branch name")
            if not target or not branch_exists(target):
                err("Not a valid local branch."); return
        if is_protected(target):
            info(f"'{target}' is a protected/mainline branch — merging your "
                 "work in is the normal way to share it. Proceeding.")
        if not _ensure_clean_tree("merge"):
            return
        # Move to the target, refresh it, then merge the source in.
        r = git("switch", target, check=False, mutating=True)
        if r.returncode != 0:
            err("Could not switch to target:\n" + (r.stderr or "").strip()); return
        ok(f"Now on '{target}'.")
        if has_remote() and upstream_of(target) and confirm(
                f"Pull latest '{target}' from {default_remote()} first "
                "(recommended)?", default_no=False):
            git("pull", "--ff-only", default_remote(), target,
                check=False, mutating=True)
        _do_merge(source, target)
        # Offer to hop back to where the user was.
        if confirm(f"Switch back to '{source}'?", default_no=False):
            git("switch", source, check=False, mutating=True)
    else:
        # Bring a chosen branch into the current one.
        opts = [(b, b + ("   [protected]" if is_protected(b) else "")) for b in branches if b != cur]
        opts.append(("__other__", "Other ref (remote branch / tag / commit)"))
        source = choose(f"Bring which branch INTO '{cur}'?", opts)
        if source is None:
            return
        if source == "__other__":
            source = ask("Ref to merge in (e.g. origin/feature/x)")
        if not source:
            return
        if not git_out("rev-parse", "--verify", "-q", f"{source}^{{commit}}"):
            err(f"'{source}' is not a valid ref."); return
        # Reversed-direction nudge: standing on a feature branch and pulling in
        # a mainline branch is often the opposite of what people intend.
        if is_protected(source) and not is_protected(cur):
            warn(f"You are about to merge mainline '{source}' INTO your branch "
                 f"'{cur}' (this updates '{cur}', NOT '{source}').")
            info(f"If your goal is to publish '{cur}' onto '{source}', cancel and "
                 "choose the other direction.")
            if not confirm("Continue merging into the current branch?"):
                info("Cancelled."); return
        if not _ensure_clean_tree("merge"):
            return
        _do_merge(source, cur)

def branch_delete():
    head("Delete a branch")
    branches = all_branches()
    cur = current_branch()
    candidates = [b for b in branches if b != cur]
    if not candidates:
        info("No other local branches to delete (can't delete the current one)."); return
    target = choose("Delete which branch?",
                    [(b, b + ("   [protected]" if is_protected(b) else ""))
                     for b in candidates])
    if target is None:
        return

    # Hard guard: mainline branches require typing the exact name to confirm.
    if is_protected(target):
        warn(f"'{target}' is a PROTECTED mainline branch. Deleting it is almost "
             "never what you want and can break everyone cloning the repo.")
        typed = ask(f"To confirm you really mean it, type the name exactly "
                    f"('{target}') — anything else cancels")
        if typed != target:
            info("Cancelled — protected branch kept safe."); return

    # Is it fully merged into the current branch? Unmerged => real data-loss risk.
    merged = git_out("branch", "--merged", default="")
    is_merged = any(line.strip().lstrip("* ").strip() == target
                    for line in merged.splitlines())
    if not is_merged:
        warn(f"'{target}' has commits NOT merged into '{cur}'. Deleting it may "
             "orphan that work (recoverable via reflog for ~90 days).")
        if not confirm("Delete anyway?"):
            info("Cancelled."); return

    pushed = remote_branch_exists(target)
    # Always leave an escape hatch: record the tip before deleting.
    tip = git_out("rev-parse", "--short", target)
    flag = "-d" if is_merged else "-D"
    r = git("branch", flag, target, check=False, mutating=True)
    if r.returncode != 0:
        err("Delete failed:\n" + (r.stderr or "").strip()); return
    ok(f"Deleted local branch '{target}' (was at {tip}).")
    info(f"Recover within ~90 days: git branch {target} {tip}")

    if pushed:
        warn(f"'{target}' also exists on {default_remote()}.")
        if is_protected(target):
            warn("This is a PROTECTED branch on the remote — deleting it there "
                 "affects everyone.")
            typed = ask(f"Type '{target}' to delete it on the remote too, "
                        "anything else keeps it")
            if typed != target:
                info("Remote branch kept."); return
        elif not confirm(f"Delete it on {default_remote()} too?"):
            return
        r = git("push", default_remote(), "--delete", target,
                check=False, mutating=True)
        ok("Remote branch deleted.") if r.returncode == 0 else err(
            "Remote delete failed:\n" + (r.stderr or "").strip())

def branch_overview():
    head("Branch overview")
    cur = current_branch()
    remote = default_remote()
    if remote:
        git("fetch", remote, check=False, mutating=True)
    for b in all_branches():
        marker = paint("*", C.OK) if b == cur else " "
        up = upstream_of(b)
        if up:
            a, be = ahead_behind(b, up)
            rel = f"\u2191{a} \u2193{be} vs {up}" if a is not None else f"tracks {up}"
        else:
            rel = paint("no upstream", C.DIM)
        tag = paint(" [protected]", C.WARN) if is_protected(b) else ""
        last = git_out("log", "-1", "--format=%cs %s", b, default="")
        print(f"   {marker} {paint(b, C.BOLD)}{tag}  {rel}")
        print(f"       {paint(last, C.DIM)}")

def flow_branch():
    while True:
        head("\U0001f333 Branches")
        act = choose("What do you want to do?", [
            ("overview", "Overview (ahead/behind vs upstream, last commit)"),
            ("new",      "Create a new branch (feature/fix/…)"),
            ("switch",   "Switch to another branch"),
            ("merge",    "Merge branches (either direction, safe, snapshot first)"),
            ("delete",   "Delete a branch (merge-checked, protected-guarded)"),
            ("rename",   "Rename a branch"),
            ("back",     "Back to main menu")])
        if act in (None, "back"):
            return
        {"overview": branch_overview, "new": branch_new, "switch": branch_switch,
         "merge": branch_merge, "delete": branch_delete,
         "rename": fix_rename_branch}[act]()

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
    valid, reason = valid_branch_name(new)
    if not valid:
        err(f"That's not a valid branch name ({reason})."); return
    if new in branches:
        err(f"'{new}' already exists."); return
    if not confirm(f"Rename '{old}' \u2192 '{new}'?", default_no=False):
        return

    pushed = has_remote() and bool(
        git_out("ls-remote", "--heads", default_remote(), old, default=""))
    git("branch", "-m", old, new, mutating=True)
    ok(f"Local branch renamed: {old} \u2192 {new}")

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
    ok(f"Local: '{old}' \u2192 '{new}' (same commit {target[:7]}, message preserved)")
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
        head("\U0001f527 Fix & Undo")
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
            ("init",    "\U0001f195 Initialize a repo from this folder (day zero)"),
            ("doctor",  "\U0001fa7a Health check (preflight doctor)"),
            ("checkin", "\u2705 Check in code  (scan \u2192 stage \u2192 commit \u2192 sync \u2192 push)"),
            ("branch",  "\U0001f333 Branches (create / switch / merge / delete)"),
            ("remote",  "\U0001f517 Remote (set up / verify / re-point / push)"),
            ("tag",     "\U0001f3f7\ufe0f  Tag a version (semver-guided, annotated)"),
            ("release", "\U0001f680 Create a release (tag + GitHub release)"),
            ("backup",  "\U0001f9f0 Backup now (worktree snapshot + full repo bundle)"),
            ("restore", "\u23ea Restore a clean tag/version (with safety net)"),
            ("fix",     "\U0001f527 Fix & Undo (rename branch/tag, amend, recover…)"),
            ("history", "\U0001f4dc Show history / tags / stashes"),
            ("quit",    "Exit")])
        if act in (None, "quit"):
            print("  bye \U0001f44b"); return
        FLOWS[act]()

FLOWS = {"init": flow_init, "doctor": doctor, "checkin": flow_checkin,
         "branch": flow_branch, "remote": flow_remote, "tag": flow_tag,
         "release": flow_release, "backup": flow_backup, "restore": flow_restore,
         "fix": flow_fix, "history": flow_history}

# Short aliases so muscle-memory works from the CLI.
ALIASES = {"ci": "checkin", "commit": "checkin", "br": "branch",
           "merge": "branch", "check": "doctor", "log": "history",
           "undo": "fix", "snapshot": "backup", "new": "init",
           "initialize": "init", "origin": "remote"}

# Commands that are valid even when the folder is NOT yet a git repo.
NO_REPO_OK = {"init", "doctor"}

VERSION = "1.6.1"

USAGE = """gitpilot v{ver} — guided, guard-railed git pipeline

Usage:
  gitpilot                 open the interactive menu
  gitpilot <command>       run one flow directly
  gitpilot --dry-run <cmd> print mutating git commands instead of running them
  gitpilot -h | --help     show this help
  gitpilot --version       show version

Commands:
  init       turn this folder into a git repo, set 'main', first commit (alias: new)
  doctor     preflight health check
  checkin    scan -> stage -> commit -> sync -> push   (aliases: ci, commit)
  branch     create / switch / merge / delete branches (aliases: br, merge)
  remote     set up / verify / re-point / push a remote  (alias: origin)
  tag        semver-guided annotated tag
  release    tag + GitHub release (needs gh)
  backup     worktree snapshot + full repo bundle       (alias: snapshot)
  restore    restore a clean tag/version with a safety net
  fix        rename branch/tag, amend, recover, stashes  (alias: undo)
  history    show recent history / tags / stashes        (alias: log)
""".format(ver=VERSION)

def _enable_windows_ansi():
    """Turn on ANSI escape processing on Windows 10+ consoles (no-op elsewhere)."""
    if os.name != "nt":
        return
    try:
        import ctypes
        k = ctypes.windll.kernel32
        k.SetConsoleMode(k.GetStdHandle(-11), 7)  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
    except Exception:
        pass

def _run_main():
    global DRY_RUN
    _enable_windows_ansi()
    args = list(sys.argv[1:])

    if "--dry-run" in args:
        DRY_RUN = True
        args.remove("--dry-run")
        warn("DRY-RUN mode: mutating git commands will be printed, not executed.")

    # Help / version work even outside a repo.
    if any(a in ("-h", "--help", "help") for a in args):
        print(USAGE); return
    if any(a in ("--version", "-V") for a in args):
        print(f"gitpilot {VERSION}"); return

    if not shutil.which("git"):
        err("git not found on PATH."); sys.exit(1)

    if args and args[0] != "menu":
        cmd = ALIASES.get(args[0], args[0])
        if cmd not in FLOWS:
            err(f"Unknown command '{args[0]}'.")
            info("Run `gitpilot --help` to see available commands.")
            sys.exit(2)
        if cmd not in NO_REPO_OK and not in_repo():
            err("Not a git repository. Run `gitpilot init` to create one from "
                "this folder, or cd into an existing repo.")
            sys.exit(1)
        FLOWS[cmd]()
    else:
        if not in_repo():
            # Offer the natural next step instead of just erroring out.
            warn("This folder is not a git repository yet.")
            if confirm("Initialize one here now with gitpilot?", default_no=False):
                flow_init()
            else:
                info("Nothing done. Run `gitpilot init` whenever you're ready.")
            return
        menu()

def main():
    try:
        _run_main()
    except KeyboardInterrupt:
        print()
        info("Interrupted. No further changes made.")
        sys.exit(130)

if __name__ == "__main__":
    main()

