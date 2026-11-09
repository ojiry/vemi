#!/usr/bin/env python3
"""Poll GitHub, isolate Claude Code, and publish only validated review fields."""
import base64
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import threading
import uuid

LIMIT = 8 * 1024 * 1024
SHA = r"[0-9a-f]{40}"
ACCOUNT = r"[A-Za-z0-9][A-Za-z0-9-]{0,38}"
REPO = ACCOUNT + r"/[A-Za-z0-9_.-]{1,100}"
API_PATH = r"/v1/messages(?:/count_tokens)?(?:\?beta=true)?"
KINDS = {
    "injection": "Potential injection vulnerability",
    "credential": "Sensitive data handling",
    "authorization": "Missing authorization check",
    "correctness": "Incorrect behavior",
    "regression": "Behavior regression",
}
ENV = {"PATH": "/usr/bin:/bin", "LANG": "en_US.UTF-8"}


class Blocked(Exception):
    """A safe, static diagnostic."""


def require(condition, reason):
    if not condition:
        raise Blocked(reason)


def matches(pattern, value):
    return isinstance(value, str) and re.fullmatch(pattern, value, re.ASCII) is not None


def private_file(root, name, maximum=32768):
    fd = os.open(root / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as source:
        info = os.fstat(source.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                and not info.st_mode & 0o077 and info.st_nlink == 1, "unsafe private file")
        data = source.read(maximum + 1)
        require(len(data) <= maximum, "private file too large")
        return data


def config(root):
    settings = json.loads(private_file(root, "review.json"))
    patterns = {
        "repository": REPO,
        "reviewer": ACCOUNT,
        "base_branch": r"[A-Za-z0-9][A-Za-z0-9._/-]{0,99}",
        "docker": r"/[^\x00\r\n]+",
        "docker_socket": r"/[^\x00\r\n]+",
        "image": r"sha256:[a-f0-9]{64}",
        "gitleaks": r"/[^\x00\r\n]+",
        "model": r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}",
    }
    require(isinstance(settings, dict) and settings.keys() ==
            patterns.keys() | {"publish_comments", "allow_approve"}, "invalid configuration")
    for key, pattern in patterns.items():
        require(matches(pattern, settings[key]), "invalid configuration value")
    for key in ("publish_comments", "allow_approve"):
        require(type(settings[key]) is bool, "invalid publishing flag")
    require(not settings["allow_approve"] or settings["publish_comments"],
            "approval requires publishing")
    return settings


def secret(root, name):
    token = private_file(root, name, 2048).decode("ascii").strip()
    require(matches(r"[A-Za-z0-9_\-.]{15,2048}", token), "invalid credential file")
    return token


def request(host, method, path, headers, body=None):
    connection = http.client.HTTPSConnection(host, timeout=45)
    try:
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        data = response.read(LIMIT + 1)
        require(len(data) <= LIMIT, "upstream response too large")
        return response.status, response.getheader("Content-Type", ""), data
    finally:
        connection.close()


class GitHub:
    def __init__(self, repository, token):
        self.repo = "/repos/" + repository
        self.headers = {
            "Authorization": "Bearer " + token,
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
            "User-Agent": "vemi-review",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def call(self, path, payload=None):
        method = "GET" if payload is None else "POST"
        body = None if payload is None else json.dumps(payload).encode()
        status, _, data = request("api.github.com", method, path, self.headers, body)
        require(status == (200 if method == "GET" else 201), "GitHub request failed")
        return json.loads(data)

    def pages(self, path, maximum):
        for page in range(1, maximum + 1):
            entries = self.call(path + f"?per_page=100&page={page}")
            require(isinstance(entries, list) and len(entries) <= 100, "invalid GitHub page")
            yield from entries
            if len(entries) < 100:
                return
        raise Blocked("GitHub pagination limit reached")

    def tree(self, commit):
        data = self.call(self.repo + f"/git/trees/{commit}?recursive=1")
        require(data["truncated"] is False and len(data["tree"]) <= 800, "tree limit reached")
        files = {}
        seen = set()
        for item in data["tree"]:
            name = item["path"]
            parts = name.split("/")
            require(len(name) <= 240 and all(matches(r"[A-Za-z0-9_.+@() -]{1,100}", part)
                    and part.lower() not in (".", "..", ".git") and not part.endswith((".", " "))
                    for part in parts), "unsupported repository path")
            require(name.lower() not in seen, "ambiguous repository path")
            seen.add(name.lower())
            if item["type"] == "tree" and item["mode"] == "040000":
                continue
            require(item["type"] == "blob" and item["mode"] in ("100644", "100755")
                    and type(item["size"]) is int and 0 <= item["size"] <= 512 * 1024
                    and matches(SHA, item["sha"]), "unsupported Git object")
            files[name] = item
        require(len(files) <= 400 and sum(i["size"] for i in files.values()) <= LIMIT,
                "snapshot limit reached")
        return files

    def blob(self, item):
        result = self.call(self.repo + "/git/blobs/" + item["sha"])
        require(result["encoding"] == "base64", "unsupported blob encoding")
        data = base64.b64decode(result["content"].replace("\n", ""), validate=True)
        digest = hashlib.sha1(f"blob {len(data)}\0".encode() + data).hexdigest()
        require(len(data) == item["size"] and digest == item["sha"], "Git blob mismatch")
        return data


def eligible(api, settings, number):
    path = api.repo + f"/pulls/{number}"
    pr = api.call(path)
    if pr["state"] != "open" or pr["draft"] is not False:
        return None
    base_repo = pr["base"]["repo"]
    if (base_repo["private"] is not False or base_repo["visibility"] != "public"
            or base_repo["full_name"].lower() != settings["repository"].lower()
            or pr["base"]["ref"] != settings["base_branch"]
            or pr["user"]["login"].lower() == settings["reviewer"].lower()):
        return None
    head_repo = pr["head"]["repo"]
    if not head_repo or head_repo["private"] is not False or head_repo["visibility"] != "public":
        return None
    head, base = pr["head"]["sha"], pr["base"]["sha"]
    require(matches(SHA, head) and matches(SHA, base), "invalid commit identity")
    reviewers = api.call(path + "/requested_reviewers")
    if not any(user["login"].lower() == settings["reviewer"].lower() for user in reviewers["users"]):
        return None
    for review in api.pages(path + "/reviews", 10):
        user = review["user"]
        if (user and user["login"].lower() == settings["reviewer"].lower()
                and (review["state"] == "PENDING" or review["commit_id"] == head)):
            return None
    return base, head, head_repo["id"] == base_repo["id"]


def write_blob(api, directory, name, item, cache):
    digest = item["sha"]
    if digest not in cache:
        cache[digest] = api.blob(item)
    target = directory / name
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("xb") as out:
        out.write(cache[digest])
    target.chmod(0o444)
    return cache[digest]


def snapshot(api, base, head, folder):
    compare = api.call(api.repo + f"/compare/{base}...{head}?per_page=1")
    ancestor = compare["merge_base_commit"]["sha"]
    require(matches(SHA, ancestor), "invalid merge base")
    before, after = api.tree(ancestor), api.tree(head)
    names = [name for name in sorted(before.keys() | after.keys())
             if before.get(name, {}).get("sha") != after.get(name, {}).get("sha")
             or before.get(name, {}).get("mode") != after.get(name, {}).get("mode")]
    require(0 < len(names) <= 100, "change count outside limits")
    cache, lines = {}, {}
    for part in ("head", "before"):
        (folder / part).mkdir()
    for name, item in after.items():
        data = write_blob(api, folder / "head", name, item, cache)
        lines[name] = data.count(b"\n") + bool(data and not data.endswith(b"\n"))
    for name in names:
        if name in before:
            write_blob(api, folder / "before", name, before[name], cache)
    manifest = [{"id": index, "path": name, "before": name in before, "head": name in after,
                 "old_mode": before.get(name, {}).get("mode"),
                 "new_mode": after.get(name, {}).get("mode")}
                for index, name in enumerate(names, 1)]
    (folder / "changes.json").write_text(json.dumps(manifest), encoding="utf-8")
    return names, lines


def scan(settings, scratch, target=None, body=None):
    args = [settings["gitleaks"], "dir" if target else "stdin", "--redact=100",
            "--no-banner", "--ignore-gitleaks-allow", "--config", str(scratch / "rules.toml"),
            "--gitleaks-ignore-path", str(scratch / "empty.ignore"),
            "--max-decode-depth=2", "--max-archive-depth=1"]
    if target:
        args.append(str(target))
    result = subprocess.run(args, cwd=scratch, env=ENV, input=body, timeout=90,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    require(result.returncode == 0, "secret scan blocked review")


def anthropic(message, token, model, request_count):
    require(set(message) == {"id", "path", "beta", "body"}
            and type(message["id"]) is int and message["id"] == request_count
            and request_count <= 64 and matches(API_PATH, message["path"])
            and matches(r"[A-Za-z0-9, ._-]{0,1024}", message["beta"]),
            "invalid inference request")
    body = base64.b64decode(message["body"], validate=True)
    payload = json.loads(body)
    require(len(body) <= LIMIT and payload["model"] == model, "invalid inference model or size")
    if "/count_tokens" not in message["path"]:
        require(type(payload["max_tokens"]) is int and 0 < payload["max_tokens"] <= 32768,
                "invalid inference token budget")
    headers = {"Content-Type": "application/json", "x-api-key": token,
               "anthropic-version": "2023-06-01"}
    if message["beta"]:
        headers["anthropic-beta"] = message["beta"]
    status, content_type, data = request("api.anthropic.com", "POST", message["path"], headers, body)
    require(status == 200, "inference API rejected request")
    require(content_type.split(";")[0] in ("application/json", "text/event-stream"),
            "invalid inference response type")
    return {"id": message["id"], "status": status, "type": content_type,
            "body": base64.b64encode(data).decode("ascii")}


def review(settings, folder, token):
    name = "vemi-review-" + uuid.uuid4().hex
    docker = [settings["docker"], "--host", "unix://" + settings["docker_socket"]]
    require("," not in str(folder), "invalid snapshot mount path")
    args = docker + [
        "run", "--rm", "--interactive", "--pull=never", "--name", name,
        "--network=none", "--cap-drop=ALL", "--security-opt=no-new-privileges:true",
        "--user=1000:1000", "--read-only", "--pids-limit=64", "--memory=768m", "--cpus=1",
        "--log-driver=none", "--tmpfs=/tmp:rw,nosuid,nodev,noexec,size=128m,mode=1777",
        "--mount", f"type=bind,src={folder},dst=/review,readonly",
        settings["image"], settings["model"],
    ]
    process = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, env=ENV)
    timer = threading.Timer(480, process.kill)
    timer.start()
    try:
        count = 0
        while True:
            line = process.stdout.readline(12 * 1024 * 1024 + 1)
            require(line.endswith(b"\n") and len(line) <= 12 * 1024 * 1024, "invalid runner output")
            message = json.loads(line)
            if set(message) == {"result"}:
                require(process.wait(timeout=5) == 0 and process.stdout.read(1) == b"",
                        "runner did not finish cleanly")
                return message["result"]
            count += 1
            response = anthropic(message, token, settings["model"], count)
            process.stdin.write(json.dumps(response).encode() + b"\n")
            process.stdin.flush()
    finally:
        timer.cancel()
        if process.poll() is None:
            process.kill()
        process.wait()
        process.stdin.close()
        process.stdout.close()
        subprocess.run(docker + ["rm", "-f", name], env=ENV, timeout=15,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def render(result, names, lines):
    require(isinstance(result, dict) and result.keys() == {"verdict", "findings"}
            and result["verdict"] in ("clean", "findings", "uncertain")
            and isinstance(result["findings"], list) and len(result["findings"]) <= 8,
            "invalid review result")
    verdict = result["verdict"]
    require(bool(result["findings"]) == (verdict == "findings"), "inconsistent review result")
    if verdict == "clean":
        return verdict, "VEMI found no issues in its static review."
    if verdict == "uncertain":
        return verdict, "VEMI could not reach a conclusion. Manual review is required."
    entries = set()
    for finding in result["findings"]:
        require(isinstance(finding, dict) and finding.keys() == {"file", "line", "kind"}
                and type(finding["file"]) is int and 1 <= finding["file"] <= len(names)
                and type(finding["line"]) is int and finding["kind"] in KINDS,
                "invalid finding")
        path = names[finding["file"] - 1]
        require(1 <= finding["line"] <= lines.get(path, 0), "invalid finding location")
        entries.add((path, finding["line"], finding["kind"]))
    body = "\n".join(f"- `{path}:{line}` - {KINDS[kind]}" for path, line, kind in sorted(entries))
    return verdict, "VEMI identified the following locations for manual review.\n\n" + body


def grant(root, repository, number, base, head):
    try:
        data = json.loads(private_file(root, "approve.json"))
    except FileNotFoundError:
        return False
    return (isinstance(data, dict) and type(data.get("pr")) is int
            and data == {"repository": repository, "pr": number, "base": base, "head": head})


def run(root):
    if os.path.lexists(root / "STOP"):
        print("VEMI stopped")
        return
    settings = config(root)
    api = GitHub(settings["repository"], secret(root, "github.token"))
    require(api.call("/user")["login"].lower() == settings["reviewer"].lower(),
            "GitHub credential identity mismatch")
    metadata = api.call(api.repo)
    require(metadata["private"] is False and metadata["visibility"] == "public",
            "repository is not public")
    for listing in api.pages(api.repo + "/pulls", 10):
        number = listing["number"]
        require(type(number) is int and number > 0, "invalid pull request number")
        version = eligible(api, settings, number)
        if version is None:
            continue
        base, head, internal = version
        with tempfile.TemporaryDirectory(prefix="review-", dir=root) as temp:
            scratch = Path(temp)
            # Docker maps a separate UID. Only the mounted snapshot needs public read bits.
            folder = scratch / "snapshot"
            folder.mkdir(mode=0o755)
            (scratch / "rules.toml").write_text("[extend]\nuseDefault = true\n")
            (scratch / "empty.ignore").touch()
            names, lines = snapshot(api, base, head, folder)
            for path in folder.rglob("*"):
                path.chmod(0o555 if path.is_dir() else 0o444)
            folder.chmod(0o555)
            try:
                scan(settings, scratch, target=folder)
                require(not os.path.lexists(root / "STOP"), "stop requested")
                require(eligible(api, settings, number) == version, "PR changed during preparation")
                result = review(settings, folder, secret(root, "anthropic.token"))
                verdict, body = render(result, names, lines)
                scan(settings, scratch, body=body.encode("utf-8"))
                if not settings["publish_comments"]:
                    print(f"VEMI dry run completed for PR #{number}")
                    return
                if eligible(api, settings, number) != version:
                    raise Blocked("PR changed during review")
                approve = (settings["allow_approve"] and internal and verdict == "clean"
                           and grant(root, settings["repository"], number, base, head))
                require(not os.path.lexists(root / "STOP"), "stop requested")
                event = "APPROVE" if approve else "COMMENT"
                api.call(api.repo + f"/pulls/{number}/reviews",
                         {"commit_id": head, "event": event, "body": body})
                print(f"VEMI {event} published for PR #{number}")
                return
            finally:
                folder.chmod(0o755)
                for path in folder.rglob("*"):
                    if path.is_dir():
                        path.chmod(0o755)
    print("VEMI found no eligible pull request")


def main():
    require(len(sys.argv) == 2 and Path(sys.argv[1]).is_absolute(), "provide private state directory")
    os.umask(0o077)
    root = Path(sys.argv[1])
    info = root.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
            and not info.st_mode & 0o077, "unsafe private directory")
    fd = os.open(root / "review.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    with os.fdopen(fd, "r+") as lock:
        require(stat.S_ISREG(os.fstat(lock.fileno()).st_mode), "unsafe lock file")
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return
        run(root)


if __name__ == "__main__":
    try:
        main()
    except Blocked as error:
        print(f"VEMI blocked: {error}", file=sys.stderr)
        sys.exit(1)
    except Exception:
        print("VEMI blocked: configuration, upstream, or runtime error", file=sys.stderr)
        sys.exit(1)
