#!/usr/bin/env python3
"""
gitpilot: a guided, guard-railed Git pipeline with an optional responsive Rich UI.

Requires: Python 3.9+ and git.
Optional: rich for the full-screen dashboard; gh for GitHub releases.

Usage:
  python3 gitpilot.py                 # Rich dashboard when supported
  python3 gitpilot.py --classic       # original-style numbered menu
  python3 gitpilot.py --rich          # require Rich dashboard
  python3 gitpilot.py doctor|checkin|tag|release|backup|restore|fix|history
  python3 gitpilot.py --dry-run <cmd>
"""
import os, re, sys, shlex, shutil, subprocess, tarfile, time
from datetime import datetime, timezone

try:
    from rich.console import Console, Group
    from rich.layout import Layout
    from rich.live import Live
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.align import Align
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

PROTECTED_BRANCHES = {"main", "master", "release", "production", "prod"}
LARGE_FILE_MB = 25
BACKUP_DIR_NAME = ".gitpilot-backups"
DRY_RUN = False

SECRET_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "AWS access key ID"),
    (r"(?i)aws(.{0,20})?(secret|private).{0,20}?[:=]\\s*['\\\"][A-Za-z0-9/+=]{40}['\\\"]", "AWS secret key"),
    (r"ghp_[A-Za-z0-9]{36}", "GitHub personal access token"),
    (r"github_pat_[A-Za-z0-9_]{22,}", "GitHub fine-grained PAT"),
    (r"gho_[A-Za-z0-9]{36}", "GitHub OAuth token"),
    (r"xox[baprs]-[A-Za-z0-9-]{10,}", "Slack token"),
    (r"sk-[A-Za-z0-9]{20,}", "API secret key (sk- prefix)"),
    (r"-----BEGIN (RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----", "Private key material"),
    (r"(?i)(password|passwd|pwd)\\s*[:=]\\s*['\\\"][^'\\\"]{6,}['\\\"]", "Hard-coded password"),
    (r"(?i)(api[_-]?key|apikey|auth[_-]?token|secret[_-]?key)\\s*[:=]\\s*['\\\"][A-Za-z0-9_\\-]{16,}['\\\"]", "Hard-coded API key/token"),
    (r"eyJ[A-Za-z0-9_-]{20,}\\.[A-Za-z0-9_-]{20,}\\.[A-Za-z0-9_-]{10,}", "JWT token"),
    (r"mysql://[^\\s'\\\"]+:[^\\s'\\\"]+@", "DB connection string with credentials"),
    (r"postgres(ql)?://[^\\s'\\\"]+:[^\\s'\\\"]+@", "DB connection string with credentials"),
    (r"mongodb(\\+srv)?://[^\\s'\\\"]+:[^\\s'\\\"]+@", "DB connection string with credentials"),
]
SKIP_SCAN_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", ".tox", ".mypy_cache", BACKUP_DIR_NAME}
SKIP_SCAN_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".pdf", ".zip", ".gz", ".tar", ".whl", ".so", ".dylib", ".dll", ".bin", ".litertlm", ".gguf", ".onnx", ".tflite", ".woff", ".woff2", ".ttf", ".ico", ".mp4", ".mp3", ".sqlite", ".db"}

class C:
    OK="\033[92m"; WARN="\033[93m"; ERR="\033[91m"; BOLD="\033[1m"; DIM="\033[2m"; CYAN="\033[96m"; END="\033[0m"
def use_color(): return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
def paint(txt, color): return f"{color}{txt}{C.END}" if use_color() else txt
def ok(msg): print(paint("  + ", C.OK)+msg)
def warn(msg): print(paint("  ! ", C.WARN)+msg)
def err(msg): print(paint("  x ", C.ERR)+msg)
def info(msg): print(paint("  > ", C.CYAN)+msg)
def head(msg): print("\n"+paint(f"-- {msg} ", C.BOLD)+paint("-"*max(0,60-len(msg)), C.DIM))
def ask(prompt, default=None):
    suffix=f" [{default}]" if default is not None else ""
    try: val=input(paint(f"  ? {prompt}{suffix}: ", C.BOLD)).strip()
    except (EOFError, KeyboardInterrupt): print(); raise UserCancelled
    return val or (default if default is not None else "")
def confirm(prompt, default_no=True):
    val=ask(f"{prompt} ({'y/N' if default_no else 'Y/n'})").lower()
    return (not default_no) if not val else val in ("y","yes")
def choose(prompt, options):
    print()
    for i,(_,label) in enumerate(options,1): print(f"    {paint(str(i), C.BOLD)}. {label}")
    while True:
        val=ask(prompt+" (number, or q to cancel)")
        if val.lower() in ("q","quit",""): return None
        if val.isdigit() and 1<=int(val)<=len(options): return options[int(val)-1][0]
        warn("Invalid choice.")
class UserCancelled(Exception): pass

def run(cmd, check=True, capture=True, mutating=False):
    if mutating and DRY_RUN:
        info("[dry-run] "+" ".join(shlex.quote(c) for c in cmd))
        return subprocess.CompletedProcess(cmd,0,"","")
    try:
        return subprocess.run(cmd,check=check,text=True,capture_output=capture)
    except FileNotFoundError as ex:
        if check: raise
        return subprocess.CompletedProcess(cmd,127,"",f"{ex.filename or cmd[0]} not found")
def git(*args, check=True, mutating=False, capture=True): return run(["git",*args],check=check,mutating=mutating,capture=capture)
def git_out(*args, default=""):
    """Return command output without destroying meaningful leading spaces.

    Git porcelain status uses the first two columns for index/worktree state.
    Calling .strip() here removed the leading space from entries such as
    " M scripts/gitpilot.py", which shifted the pathname to
    "cripts/gitpilot.py". Only line-ending characters are removed.
    """
    try:
        return git(*args).stdout.rstrip("\r\n")
    except subprocess.CalledProcessError:
        return default
def in_repo(): return git_out("rev-parse","--is-inside-work-tree")=="true"
def repo_root(): return git_out("rev-parse","--show-toplevel")
def git_dir():
    gd=git_out("rev-parse","--git-dir")
    if not gd: return ""
    return os.path.realpath(gd if os.path.isabs(gd) else os.path.join(os.getcwd(),gd))
def current_branch():
    br=git_out("rev-parse","--abbrev-ref","HEAD")
    return br or git_out("symbolic-ref","--short","-q","HEAD") or "HEAD"
def has_commits(): return bool(git_out("rev-parse","--verify","-q","HEAD"))
def has_remote(): return bool(git_out("remote"))
def default_remote():
    rs=git_out("remote").splitlines(); return "origin" if "origin" in rs else (rs[0] if rs else None)
def upstream_of(branch): return git_out("rev-parse","--abbrev-ref",f"{branch}@{{upstream}}",default="")
def dirty_files():
    out=git_out("status","--porcelain=v1"); return out.splitlines() if out else []
def repo_in_progress_state():
    gd=git_dir(); states=[]
    if not gd: return states
    for f,label in [("MERGE_HEAD","merge"),("REBASE_HEAD","rebase"),("CHERRY_PICK_HEAD","cherry-pick"),("BISECT_LOG","bisect")]:
        if os.path.exists(os.path.join(gd,f)): states.append(label)
    if os.path.isdir(os.path.join(gd,"rebase-merge")) or os.path.isdir(os.path.join(gd,"rebase-apply")):
        if "rebase" not in states: states.append("rebase")
    return states
def timestamp(): return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
def divergence(up):
    vals=git_out("rev-list","--left-right","--count",f"{up}...HEAD").split()
    try: return int(vals[0]),int(vals[1])
    except (ValueError,IndexError): return 0,0

def doctor(verbose=True):
    head("Preflight health check"); healthy=True
    if not shutil.which("git"): err("git is not installed or not on PATH."); return False
    ok(f"git found: {git_out('--version')}")
    if not in_repo(): err("Not inside a git repository."); return False
    ok(f"Repository root: {repo_root()}")
    name,email=git_out("config","user.name"),git_out("config","user.email")
    if not name or not email:
        warn("git user.name / user.email is not fully configured.")
        if confirm("Set missing identity values now?",False):
            if not name:
                n=ask("Your name");
                if n: git("config","user.name",n,mutating=True)
            if not email:
                e=ask("Your email");
                if e: git("config","user.email",e,mutating=True)
        else: healthy=False
    else: ok(f"Committer identity: {name} <{email}>")
    br=current_branch()
    if br=="HEAD": err("Detached HEAD. Create a branch before committing."); healthy=False
    else:
        ok(f"Current branch: {br}")
        if br in PROTECTED_BRANCHES: warn(f"'{br}' is protected; prefer a feature branch.")
    states=repo_in_progress_state()
    if states: err(f"Operation in progress: {', '.join(states)}."); healthy=False
    conflicts=git_out("diff","--name-only","--diff-filter=U")
    if conflicts: err("Unresolved conflicts: "+conflicts.replace("\n",", ")); healthy=False
    if has_remote():
        r=default_remote(); ok(f"Remote: {r} -> {git_out('remote','get-url',r)}")
    else: warn("No remote configured. Local commit/tag/backup still work.")
    if not os.path.exists(os.path.join(repo_root(),".gitignore")): warn("No .gitignore found.")
    info("GitHub CLI available." if shutil.which("gh") else "GitHub CLI not found; releases can be created manually.")
    d=dirty_files(); info(f"{len(d)} file(s) with uncommitted changes.") if d else ok("Working tree is clean.")
    print(); print(paint("  Overall: ",C.BOLD)+(paint("READY",C.OK) if healthy else paint("ISSUES FOUND",C.ERR)))
    return healthy

def normalize_status_path(line):
    path=line[3:]
    if " -> " in path: path=path.split(" -> ",1)[1]
    return path.strip('"')
def scan_secrets(paths):
    findings=[]; root=repo_root()
    for rel in paths:
        p=os.path.join(root,rel)
        if not os.path.isfile(p) or os.path.splitext(p)[1].lower() in SKIP_SCAN_EXT or any(x in SKIP_SCAN_DIRS for x in rel.split(os.sep)): continue
        try:
            if os.path.getsize(p)>2*1024*1024: continue
            with open(p,"r",encoding="utf-8",errors="ignore") as f:
                for ln,line in enumerate(f,1):
                    for pat,label in SECRET_PATTERNS:
                        if re.search(pat,line): findings.append((rel,ln,label))
        except OSError: pass
    return findings
def scan_large(paths):
    out=[]; root=repo_root()
    for rel in paths:
        p=os.path.join(root,rel)
        if os.path.isfile(p):
            mb=os.path.getsize(p)/(1024*1024)
            if mb>=LARGE_FILE_MB: out.append((rel,mb))
    return out

def backup_dir():
    d=os.path.join(repo_root(),BACKUP_DIR_NAME); os.makedirs(d,exist_ok=True)
    ex=os.path.join(git_dir(),"info","exclude")
    try:
        existing=""
        if os.path.exists(ex):
            with open(ex,"r",encoding="utf-8") as f: existing=f.read()
        rule=f"{BACKUP_DIR_NAME}/"
        if rule not in existing.splitlines():
            with open(ex,"a",encoding="utf-8") as f: f.write("\n"+rule+"\n")
    except OSError: pass
    return d
def snapshot_worktree(label="manual"):
    dest=os.path.join(backup_dir(),f"worktree-{label}-{timestamp()}.tar.gz"); root=repo_root()
    if DRY_RUN: info(f"[dry-run] would create {dest}"); return dest
    def filt(ti): return None if any(x in (".git",BACKUP_DIR_NAME) for x in ti.name.split("/")) else ti
    with tarfile.open(dest,"w:gz") as tar: tar.add(root,arcname=os.path.basename(root),filter=filt)
    ok("Worktree snapshot: "+os.path.relpath(dest,root)); return dest
def bundle_repo(label="manual"):
    dest=os.path.join(backup_dir(),f"repo-{label}-{timestamp()}.bundle")
    r=git("bundle","create",dest,"--all",check=False,mutating=True)
    if r.returncode==0: ok("Full repository bundle: "+os.path.relpath(dest,repo_root()))
    else: err("Bundle creation failed: "+r.stderr.strip())
    return dest
def prune_old_backups(keep=10):
    files=sorted((os.path.join(backup_dir(),f) for f in os.listdir(backup_dir())),key=os.path.getmtime,reverse=True)
    for old in files[keep:]:
        try: os.remove(old); info("Pruned: "+os.path.basename(old))
        except OSError: pass
def flow_backup():
    head("Backup"); snapshot_worktree(); bundle_repo(); prune_old_backups()

def flow_restore():
    head("Restore a clean tag or version")
    tags=git_out("tag","--sort=-creatordate").splitlines(); target=None
    if tags:
        opts=[(t,f"tag {t}  {git_out('log','-1','--format=%cs %s',t)}") for t in tags[:15]]+[("__other__","Enter another ref")]
        target=choose("Restore which version?",opts)
        if target=="__other__": target=ask("Ref")
    else: target=ask("Ref to restore")
    if not target: return
    if not git_out("rev-parse","--verify",f"{target}^{{commit}}"): err(f"'{target}' is not valid."); return
    mode=choose("Restore mode",[("inspect","Inspect on a temporary branch"),("overlay","Overlay files as new working changes"),("hard","Hard reset current branch, with safety backup")])
    if not mode: return
    safe=re.sub(r"[^A-Za-z0-9._-]","_",target); snapshot_worktree(f"pre-restore-{safe}"); br=current_branch()
    if dirty_files():
        git("stash","push","--include-untracked","-m",f"gitpilot pre-restore {timestamp()}",mutating=True); ok("Changes stashed.")
    rescue=None
    if br!="HEAD":
        rescue=f"rescue/{br}-{timestamp()}"; git("branch",rescue,mutating=True); ok(f"Rescue branch: {rescue}")
    if mode=="inspect":
        tmp=f"inspect/{safe}-{timestamp()}"; git("switch","-c",tmp,target,mutating=True); ok(f"Now on {tmp}.")
    elif mode=="overlay":
        git("checkout",target,"--",".",mutating=True); ok(f"Files from {target} staged on {br}.")
    else:
        warn(f"This moves '{br}' to {target}.")
        if not confirm("Proceed with hard reset?"): info("Cancelled."); return
        bundle_repo("pre-hard-reset"); git("reset","--hard",target,mutating=True); ok(f"Reset complete. Undo via {rescue}.")

CTYPES=[("feat","feat - new feature"),("fix","fix - bug fix"),("docs","docs - documentation"),("refactor","refactor - no behavior change"),("perf","perf - performance"),("test","test - tests"),("chore","chore - tooling"),("style","style - formatting"),("__free__","Free-form message")]
def flow_checkin():
    if not doctor(False) and not confirm("Health check found issues. Continue anyway?"): return
    head("Guided check-in"); d=dirty_files()
    if not d: ok("Nothing to commit."); _maybe_push_ahead(); return
    paths=[]
    for line in d[:60]: paths.append(normalize_status_path(line)); print(f"    {line[:2]} {line[3:]}")
    if len(d)>60: info(f"... and {len(d)-60} more")
    findings=scan_secrets(paths)
    if findings:
        head("Possible secrets detected")
        for rel,ln,label in findings[:20]: err(f"{rel}:{ln} - {label}")
        if not confirm("Proceed anyway, not recommended?"): return
    big=scan_large(paths)
    if big:
        for rel,mb in big: warn(f"Large file: {rel} ({mb:.1f} MB)")
        if not confirm("Include large files anyway?"): return
    br=current_branch()
    if br in PROTECTED_BRANCHES and confirm("Create a feature branch instead?",False):
        nb=ask("New branch",f"feature/{timestamp()}"); git("switch","-c",nb,mutating=True)
    stage=choose("What should be staged?",[("all","Everything"),("tracked","Tracked files only"),("pick","Pick files"),("patch","Interactive hunks")])
    if not stage: return
    if stage=="all": git("add","-A",mutating=True)
    elif stage=="tracked": git("add","-u",mutating=True)
    elif stage=="pick":
        for p in paths:
            if confirm(f"Stage {p}?",False): git("add","--",p,mutating=True)
    else:
        if DRY_RUN: info("[dry-run] git add -p")
        else: subprocess.run(["git","add","-p"],check=False)
    staged=git_out("diff","--cached","--name-only")
    if not staged: warn("Nothing staged. In dry-run mode this reflects the real index."); return
    ctype=choose("Commit type?",CTYPES)
    if not ctype: return
    if ctype=="__free__": msg=ask("Commit message")
    else:
        scope=ask("Scope, optional",""); subject=ask("Short imperative description")
        msg=f"{ctype}({scope}): {subject}" if scope else f"{ctype}: {subject}"
        body=ask("Longer body, optional","")
        if body: msg+="\n\n"+body
    if not msg.strip(): warn("Empty message."); return
    r=git("commit","-m",msg,check=False,mutating=True)
    if r.returncode: err("Commit failed: "+r.stderr.strip()); return
    ok("Committed: "+msg.splitlines()[0]); _maybe_push_ahead()
def _maybe_push_ahead():
    if not has_remote(): info("No remote; stopping after local work."); return
    br=current_branch(); remote=default_remote()
    if br=="HEAD": return
    head("Sync with remote")
    r=git("fetch",remote,check=False,mutating=True)
    if r.returncode: err("Fetch failed: "+r.stderr.strip()); return
    up=upstream_of(br)
    if not up:
        if confirm(f"Push and set upstream to {remote}/{br}?",False):
            r=git("push","-u",remote,br,check=False,mutating=True); ok("Pushed.") if not r.returncode else err(r.stderr.strip())
        return
    behind,ahead=divergence(up)
    if behind:
        act=choose(f"Branch is {behind} commit(s) behind. Integrate how?",[("rebase","Rebase, recommended"),("merge","Merge"),("skip","Skip")])
        if act=="rebase": r=git("pull","--rebase",remote,br,check=False,mutating=True)
        elif act=="merge": r=git("pull","--no-rebase",remote,br,check=False,mutating=True)
        else: return
        if r.returncode: err("Integration stopped with conflicts. Resolve or abort, then rerun."); return
        behind,ahead=divergence(up)
    if behind: warn("Still behind upstream; push skipped."); return
    if ahead and confirm(f"Push {ahead} commit(s) to {remote}?",False):
        r=git("push",remote,br,check=False,mutating=True); ok("Pushed.") if not r.returncode else err("Push failed: "+r.stderr.strip())
    elif not ahead: ok("Branch is up to date.")

SEMVER_RE=re.compile(r"^v?(\\d+)\\.(\\d+)\\.(\\d+)$")
def latest_semver():
    for t in git_out("tag","--sort=-v:refname").splitlines():
        m=SEMVER_RE.match(t)
        if m: return t,tuple(int(x) for x in m.groups())
    return None,None
def flow_tag():
    head("Guided tagging")
    if not has_commits(): warn("No commits to tag."); return
    if dirty_files() and not confirm("Uncommitted work will not be tagged. Continue?"): return
    last,ver=latest_semver()
    if ver:
        a,b,c=ver; p="v" if last.startswith("v") else ""
        tag=choose("Release type",[(f"{p}{a}.{b}.{c+1}","Patch"),(f"{p}{a}.{b+1}.0","Minor"),(f"{p}{a+1}.0.0","Major"),("__custom__","Custom")])
        if tag=="__custom__": tag=ask("Tag")
    else: tag=ask("Tag","v0.1.0")
    if not tag: return
    if git_out("rev-parse","--verify",f"refs/tags/{tag}"): err("Tag already exists."); return
    rng=f"{last}..HEAD" if last else "HEAD"; log=git_out("log",rng,"--format=- %s")
    if log: head("Changes"); print(log)
    msg=ask("Tag message",f"Release {tag}"); r=git("tag","-a",tag,"-m",msg+("\n\n"+log if log else ""),check=False,mutating=True)
    if r.returncode: err(r.stderr.strip()); return
    ok(f"Created {tag}.")
    if has_remote() and confirm(f"Push tag to {default_remote()}?",False): git("push",default_remote(),tag,mutating=True)
    return tag,log
def flow_release():
    head("Guided release"); tags=git_out("tag","--sort=-creatordate").splitlines()
    if tags and confirm(f"Use latest tag '{tags[0]}'?",False):
        tag=tags[0]; log=git_out("log",f"{tags[1]}..{tag}" if len(tags)>1 else tag,"--format=- %s")
    else:
        res=flow_tag()
        if not res: return
        tag,log=res
    if shutil.which("gh"):
        auth=run(["gh","auth","status"],check=False)
        if auth.returncode: warn("Run 'gh auth login' first."); return _manual_release_notes(tag)
        if confirm(f"Create GitHub release for {tag}?",False):
            r=run(["gh","release","create",tag,"--title",tag,"--notes",log or f"Release {tag}"],check=False,mutating=True)
            ok("GitHub release created.") if not r.returncode else err(r.stderr.strip())
    else: _manual_release_notes(tag)
def _manual_release_notes(tag):
    r=default_remote() or "origin"; info(f"Push tag: git push {r} {tag}"); info("Then create a release in your hosting service and select the tag.")

def _is_pushed(ref):
    if not has_remote(): return False
    r=default_remote(); git("fetch",r,"--tags",check=False,mutating=True)
    return bool(git_out("branch","-r","--contains",ref) or git_out("ls-remote","--tags",r,ref))
def fix_rename_branch():
    branches=git_out("branch","--format=%(refname:short)").splitlines(); old=choose("Branch",[(b,b) for b in branches])
    if not old: return
    new=ask("New name")
    if not new or git_out("check-ref-format","--branch",new,default="__bad__")=="__bad__" or new in branches: err("Invalid or existing branch name."); return
    pushed=has_remote() and bool(git_out("ls-remote","--heads",default_remote(),old)); git("branch","-m",old,new,mutating=True); ok(f"Renamed {old} to {new}.")
    if pushed and confirm("Update remote branch too?"):
        git("push","-u",default_remote(),new,mutating=True); git("push",default_remote(),"--delete",old,mutating=True)
def fix_rename_tag():
    tags=git_out("tag","--sort=-creatordate").splitlines(); old=choose("Tag",[(t,t) for t in tags[:20]]) if tags else None
    if not old: return
    new=ask("New tag")
    if not new or new in tags: err("Invalid or existing tag."); return
    target=git_out("rev-parse",f"{old}^{{commit}}"); msg=git_out("tag","-l","--format=%(contents)",old) or f"Release {new}"; pushed=_is_pushed(old)
    if pushed and not confirm("Pushed tags should be immutable. Rename remotely anyway?"): return
    git("tag","-a",new,target,"-m",msg,mutating=True); git("tag","-d",old,mutating=True)
    if pushed: git("push",default_remote(),new,mutating=True); git("push",default_remote(),f":refs/tags/{old}",mutating=True)
def fix_amend_message():
    if not has_commits(): return info("No commits.")
    pushed=_is_pushed("HEAD")
    if pushed and not confirm("Pushed commit. Amend only on your personal branch?"): return
    msg=ask("New message")
    if msg: git("commit","--amend","-m",msg,mutating=True); ok("Amended.")
    if pushed: info("Update with git push --force-with-lease")
def fix_add_to_last():
    if not has_commits() or not dirty_files(): return info("Nothing available to amend.")
    if _is_pushed("HEAD") and not confirm("Pushed commit. Amend personal branch only?"): return
    git("add","-A",mutating=True); git("commit","--amend","--no-edit",mutating=True); ok("Changes folded into last commit.")
def fix_undo_last_commit():
    if not has_commits(): return info("No commits.")
    if _is_pushed("HEAD"):
        act=choose("Pushed commit",[("revert","Create safe revert"),("reset","Soft reset personal branch")])
        if act=="revert": git("revert","--no-edit","HEAD",mutating=True); return
        if not act: return
    if confirm("Undo last commit but keep changes?"): git("reset","--soft","HEAD~1",mutating=True); ok("Commit undone; changes staged.")
def fix_unstage_or_discard():
    act=choose("Action",[("unstage","Unstage all, keep edits"),("discard","Discard tracked edits after snapshot")])
    if act=="unstage": git("restore","--staged",".",mutating=True); ok("Unstaged.")
    elif act=="discard" and confirm("Snapshot then discard tracked edits?"): snapshot_worktree("pre-discard"); git("restore",".",mutating=True); ok("Discarded.")
def fix_reflog_rescue():
    print(git_out("reflog","--date=relative","-20")); sha=ask("Commit ID, Enter to cancel")
    if not sha: return
    if not git_out("rev-parse","--verify","-q",f"{sha}^{{commit}}"): return err("Invalid commit.")
    name=ask("Rescue branch",f"rescue/{sha[:7]}"); git("branch",name,sha,mutating=True); ok(f"Created {name}.")
def fix_stash_manager():
    entries=git_out("stash","list").splitlines()
    if not entries: return info("No stashes.")
    print("\n".join(entries)); idx=ask("Stash number")
    if not idx.isdigit(): return
    ref=f"stash@{{{idx}}}"; act=choose("Action",[("apply","Apply, keep stash"),("pop","Pop"),("branch","Apply on new branch"),("drop","Delete stash")])
    if act in ("apply","pop"): git("stash",act,ref,mutating=True)
    elif act=="branch": git("stash","branch",ask("Branch",f"stash-work-{timestamp()}"),ref,mutating=True)
    elif act=="drop" and confirm("Delete stash?"): git("stash","drop",ref,mutating=True)
def flow_fix():
    funcs={"branch":fix_rename_branch,"tag":fix_rename_tag,"msg":fix_amend_message,"add":fix_add_to_last,"undo":fix_undo_last_commit,"changes":fix_unstage_or_discard,"reflog":fix_reflog_rescue,"stash":fix_stash_manager}
    while True:
        act=choose("Fix and Undo",[("branch","Rename branch"),("tag","Rename tag"),("msg","Amend last message"),("add","Add files to last commit"),("undo","Undo last commit, keep work"),("changes","Unstage or discard"),("reflog","Rescue from reflog"),("stash","Manage stashes"),("back","Back")])
        if act in (None,"back"): return
        funcs[act]()
def flow_history():
    head("Recent history"); print(git_out("log","--oneline","--graph","--decorate","-15") or "  no commits")
    head("Tags"); print(git_out("tag","--sort=-creatordate","-n1") or "  no tags")
    st=git_out("stash","list")
    if st: head("Stashes"); print(st)

def parse_porcelain_status():
    result={"staged":[],"modified":[],"untracked":[],"conflicted":[]}; conflicts={"DD","AU","UD","UA","DU","AA","UU"}
    for line in git_out("status","--porcelain=v1","--untracked-files=normal").splitlines():
        if len(line)<3: continue
        xy,path=line[:2],normalize_status_path(line)
        if xy=="??": result["untracked"].append(path)
        elif xy in conflicts: result["conflicted"].append(path)
        else:
            if xy[0] not in (" ","?"): result["staged"].append(path)
            if xy[1] not in (" ","?"): result["modified"].append(path)
    return result
def collect_dashboard_state():
    br=current_branch(); s=parse_porcelain_status(); up=upstream_of(br); behind,ahead=divergence(up) if up else (0,0); root=repo_root(); remote=default_remote()
    return {**s,"root":root,"repo_name":os.path.basename(root),"branch":br,"upstream":up,"behind":behind,"ahead":ahead,"remote":remote or "","remote_url":git_out("remote","get-url",remote) if remote else "","states":repo_in_progress_state(),"last_commit":git_out("log","-1","--format=%h  %s") if has_commits() else "","has_gh":bool(shutil.which("gh")),"dry_run":DRY_RUN}

class KeyReader:
    def __init__(self): self.windows=os.name=="nt"; self.fd=None; self.old=None
    def __enter__(self):
        if not self.windows:
            import termios,tty; self.fd=sys.stdin.fileno(); self.old=termios.tcgetattr(self.fd); tty.setcbreak(self.fd)
        return self
    def __exit__(self,*_):
        if not self.windows and self.old is not None:
            import termios; termios.tcsetattr(self.fd,termios.TCSADRAIN,self.old)
    def read(self,timeout=.20):
        if self.windows:
            import msvcrt
            if not msvcrt.kbhit(): time.sleep(timeout); return None
            k=msvcrt.getwch()
            if k in ("\x00","\xe0"):
                if msvcrt.kbhit(): msvcrt.getwch()
                return None
            return k
        import select
        ready,_,_=select.select([sys.stdin],[],[],timeout); return sys.stdin.read(1) if ready else None

class GitPilotDashboard:
    """Responsive dashboard plus an embedded pseudo-terminal workflow pane."""

    ACTIONS={"d":"doctor","c":"checkin","t":"tag","r":"release",
             "b":"backup","o":"restore","f":"fix","h":"history"}

    def __init__(self):
        self.console=Console()
        self.view="status"
        self.notice=""
        self.state=collect_dashboard_state()
        self.child_pid=None
        self.child_fd=None
        self.child_done=False
        self.child_exit=None
        self.workflow_name=""
        self.output=""
        self.scroll_offset=0

    def header(self):
        title="🚀 GitPilot" if self.console.size.width<55 else "🚀 GitPilot | Guided Git Pipeline"
        extra=[]
        if DRY_RUN: extra.append("DRY RUN")
        if self.state["states"]: extra.append(" / ".join(self.state["states"]).upper())
        suffix=("  ["+", ".join(extra)+"]") if extra else ""
        return Panel(Align.center(Text(title+suffix,style="bold cyan")),height=3,border_style="bright_blue")

    def nav(self):
        t=Text(justify="center")
        items=[("status","[S]tatus"),("changes","[D]iff"),("actions","[A]ctions")]
        for key,label in items:
            active=self.view==key
            t.append(f" {label} ",style="bold black on bright_green" if active else "dim white")
            t.append(" ")
        return Panel(t,height=3,border_style="dim")

    def status(self):
        s=self.state
        body=Text()
        body.append(f"Branch: {s['branch']}\n\n",style="bold yellow")
        groups=[("Staged",s["staged"],"green"),("Modified",s["modified"],"red"),
                ("Untracked",s["untracked"],"cyan"),("Conflicted",s["conflicted"],"bold red")]
        available=max(8,self.console.size.height-15)
        limit=max(2,available//max(1,sum(bool(files) for _,files,_ in groups)))
        for title,files,style in groups:
            if not files: continue
            body.append(f"{title} ({len(files)}):\n",style=style)
            for path in files[:limit]: body.append("  • ",style=style); body.append(path+"\n",style=style)
            if len(files)>limit: body.append(f"  … {len(files)-limit} more\n",style="dim")
            body.append("\n")
        if not any(files for _,files,_ in groups): body.append("✓ Working tree is clean.\n",style="bold green")
        sync=s["upstream"] or "no upstream"
        if s["upstream"]: sync+=f"  ↑{s['ahead']} ↓{s['behind']}"
        body.append(f"Upstream: {sync}\n",style="dim")
        if s["last_commit"]: body.append(f"Last commit: {s['last_commit']}",style="dim")
        return Panel(body,title="[bold green]Status[/bold green]",border_style="green",expand=True)

    def changes(self):
        body=Text()
        diff=git_out("diff","--color=always","--stat")
        staged=git_out("diff","--cached","--color=always","--stat")
        if staged:
            body.append("STAGED\n",style="bold green")
            body.append_text(Text.from_ansi(staged)); body.append("\n\n")
        if diff:
            body.append("WORKING TREE\n",style="bold yellow")
            body.append_text(Text.from_ansi(diff)); body.append("\n")
        if not staged and not diff:
            body.append("No tracked-file differences.\n",style="green")
            if self.state["untracked"]:
                body.append("\nUntracked files:\n",style="bold cyan")
                for path in self.state["untracked"]: body.append(f"  • {path}\n",style="cyan")
        return Panel(body,title="[bold yellow]Diff summary[/bold yellow]",border_style="yellow",expand=True)

    def actions(self):
        rows=[("🩺","D","Doctor","Preflight health check"),
              ("✅","C","Check in","Scan → stage → commit → sync → push"),
              ("🏷️","T","Tag","Semver-guided annotated tag"),
              ("🚀","R","Release","Tag plus GitHub release"),
              ("🧰","B","Backup","Worktree snapshot plus repository bundle"),
              ("⏪","O","Restore","Safe tag or version restore"),
              ("🔧","F","Fix & Undo","Amend, undo, rename or recover"),
              ("📜","H","History","Commits, tags and stashes")]
        table=Table(expand=True,box=None,show_header=False,padding=(0,1))
        table.add_column(width=3); table.add_column(width=5,style="bold cyan")
        table.add_column(style="bold white"); table.add_column(style="dim")
        narrow=self.console.size.width<65
        for icon,key,name,desc in rows: table.add_row(icon,f"[{key}]",name,"" if narrow else desc)
        return Panel(table,title="[bold magenta]Workflows[/bold magenta]",border_style="magenta",expand=True)

    def visible_output(self):
        """Render the child pseudo-terminal output inside the main panel."""
        clean=self.output.replace("\x1b[?2004h","").replace("\x1b[?2004l","")
        lines=clean.splitlines()
        height=max(4,self.console.size.height-12)
        max_offset=max(0,len(lines)-height)
        self.scroll_offset=max(0,min(self.scroll_offset,max_offset))
        end=len(lines)-self.scroll_offset
        start=max(0,end-height)
        visible="\n".join(lines[start:end])
        text=Text.from_ansi(visible) if visible else Text("Starting workflow…",style="dim")
        title=f"[bold cyan]{self.workflow_name}[/bold cyan]"
        if self.child_done:
            title+=f"  [dim](exit {self.child_exit})[/dim]"
        return Panel(text,title=title,border_style="cyan",expand=True)

    def footer_text(self):
        if self.view=="workflow":
            if self.child_done:
                return "[Space/PgDn] Scroll down  [PgUp] Scroll up  [Home/End] Jump  [Enter/Esc] Back"
            return "Type responses normally  [Ctrl+U/Ctrl+D] Scroll  [Ctrl+C] Interrupt"
        return "[S] Status  [D] Diff  [A] Actions  [U] Refresh  [Q] Quit"

    def layout(self):
        layout=Layout()
        if self.view=="workflow":
            layout.split_column(Layout(name="head",size=3),Layout(name="main",ratio=1),Layout(name="foot",size=3))
            layout["head"].update(self.header()); layout["main"].update(self.visible_output())
        else:
            layout.split_column(Layout(name="head",size=3),Layout(name="nav",size=3),Layout(name="main",ratio=1),Layout(name="foot",size=3))
            layout["head"].update(self.header()); layout["nav"].update(self.nav())
            main=self.status() if self.view=="status" else self.changes() if self.view=="changes" else self.actions()
            layout["main"].update(main)
        footer=self.notice or self.footer_text()
        layout["foot"].update(Panel(Align.center(Text.from_markup(footer)),height=3,border_style="dim"))
        return layout

    def start_workflow(self,action):
        """Run an existing flow in a child PTY while keeping the Rich frame."""
        if os.name=="nt":
            self.notice="Embedded workflow view requires Linux, macOS, WSL or Termux."
            return False
        import pty
        pid,fd=pty.fork()
        if pid==0:
            args=[sys.executable,os.path.abspath(__file__)]
            if DRY_RUN: args.append("--dry-run")
            args.append(action)
            os.execv(sys.executable,args)
        self.child_pid,self.child_fd=pid,fd
        os.set_blocking(fd,False)
        self.child_done=False; self.child_exit=None; self.workflow_name=action.replace("_"," ").title()
        self.output=""; self.scroll_offset=0; self.view="workflow"; self.notice=""
        return True

    def pump_child(self):
        if self.child_fd is None or self.child_done: return
        try:
            while True:
                block=os.read(self.child_fd,65536)
                if not block: break
                self.output+=block.decode("utf-8",errors="replace")
                if self.scroll_offset==0: self.scroll_offset=0
        except BlockingIOError:
            pass
        except OSError:
            pass
        try:
            pid,status=os.waitpid(self.child_pid,os.WNOHANG)
        except ChildProcessError:
            pid,status=self.child_pid,0
        if pid:
            self.child_done=True
            self.child_exit=os.waitstatus_to_exitcode(status) if hasattr(os,"waitstatus_to_exitcode") else status
            try:
                while True:
                    block=os.read(self.child_fd,65536)
                    if not block: break
                    self.output+=block.decode("utf-8",errors="replace")
            except (BlockingIOError,OSError): pass
            try: os.close(self.child_fd)
            except OSError: pass
            self.child_fd=None

    def send_child(self,key):
        if self.child_fd is not None:
            try: os.write(self.child_fd,key.encode("utf-8"))
            except OSError: pass

    def handle_workflow_key(self,key):
        if not key: return
        if self.child_done:
            page=max(3,self.console.size.height-14)
            if key in ("\r","\n","\x1b"):
                self.state=collect_dashboard_state(); self.view="actions"; self.notice="Workflow complete"
            elif key==" ": self.scroll_offset=max(0,self.scroll_offset-page)
            elif key=="\x15": self.scroll_offset+=page
            elif key=="\x04": self.scroll_offset=max(0,self.scroll_offset-page)
            return
        if key=="\x15": self.scroll_offset+=max(3,self.console.size.height-14)   # Ctrl+U
        elif key=="\x04": self.scroll_offset=max(0,self.scroll_offset-max(3,self.console.size.height-14)) # Ctrl+D
        else: self.send_child(key)

    def run(self):
        self.state=collect_dashboard_state()
        with KeyReader() as reader:
            with Live(self.layout(),console=self.console,screen=True,auto_refresh=False,
                      redirect_stdout=False,redirect_stderr=False) as live:
                while True:
                    if self.view=="workflow": self.pump_child()
                    key=reader.read(.05)
                    if self.view=="workflow":
                        self.handle_workflow_key(key)
                    elif key:
                        k=key.lower(); self.notice=""
                        if k in ("q","\x03"): return
                        if k=="s": self.view="status"
                        elif k=="d": self.view="changes"
                        elif k in ("a","\r","\n"): self.view="actions"
                        elif k=="u": self.state=collect_dashboard_state(); self.notice="Repository refreshed"
                        elif k in self.ACTIONS: self.start_workflow(self.ACTIONS[k])
                        else: self.notice=f"Unknown key: {repr(k)}"
                    live.update(self.layout(),refresh=True)

def menu():
    while True:
        act=choose("GitPilot",[("doctor","🩺 Health check"),("checkin","✅ Check in code"),("tag","🏷️ Tag version"),("release","🚀 Create release"),("backup","🧰 Backup"),("restore","⏪ Restore"),("fix","🔧 Fix and Undo"),("history","📜 History"),("quit","Exit")])
        if act in (None,"quit"): print("  bye 👋"); return
        try: FLOWS[act]()
        except UserCancelled: warn("Cancelled.")

def rich_menu():
    GitPilotDashboard().run()

def rich_ui_diagnostics():
    """Return reasons why the fullscreen dashboard cannot be used."""
    reasons=[]
    if not RICH_AVAILABLE: reasons.append("the Python package 'rich' is not installed")
    if not sys.stdin.isatty(): reasons.append("standard input is not an interactive terminal")
    if not sys.stdout.isatty(): reasons.append("standard output is not an interactive terminal")
    if os.environ.get("TERM", "").lower() == "dumb": reasons.append("TERM is set to 'dumb'")
    if os.environ.get("GITPILOT_CLASSIC"): reasons.append("GITPILOT_CLASSIC is set")
    return reasons

def can_use_rich_ui():
    return not rich_ui_diagnostics()

FLOWS={"doctor":doctor,"checkin":flow_checkin,"tag":flow_tag,"release":flow_release,"backup":flow_backup,"restore":flow_restore,"fix":flow_fix,"history":flow_history}
def main():
    global DRY_RUN
    args=list(sys.argv[1:]); force_classic="--classic" in args; force_rich="--rich" in args
    for flag in ("--classic","--rich"):
        if flag in args: args.remove(flag)
    if "--dry-run" in args:
        DRY_RUN=True; args.remove("--dry-run"); warn("DRY-RUN: mutations are printed, not executed; later decisions use the real repository state.")
    if not shutil.which("git"): err("git not found on PATH."); return 1
    if args and args[0]!="menu":
        cmd=args[0]
        if cmd not in FLOWS: err(f"Unknown command '{cmd}'. Options: {', '.join(FLOWS)}"); return 2
        if cmd!="doctor" and not in_repo(): err("Not a git repository."); return 1
        try: FLOWS[cmd]()
        except UserCancelled: warn("Cancelled.")
        return 0
    if not in_repo(): err("Not a git repository. cd into a project or run git init first."); return 1
    if force_rich and not RICH_AVAILABLE: err("Rich UI requested but Rich is not installed. Run: python3 -m pip install rich"); return 1
    if force_classic:
        menu()
    elif can_use_rich_ui():
        rich_menu()
    else:
        reasons=rich_ui_diagnostics()
        err("The fullscreen GitPilot dashboard could not start.")
        for reason in reasons: print(f"    - {reason}")
        if not RICH_AVAILABLE:
            print("\n  Install the dashboard dependency with:")
            print("    python3 -m pip install --user rich")
            print("\n  On Termux, this is usually:")
            print("    python -m pip install rich")
        print("\n  Then run:")
        print("    python3 gitpilot.py --rich")
        print("\n  Use --classic only when you intentionally want the numbered menu.")
        return 1
    return 0
if __name__=="__main__": raise SystemExit(main())

