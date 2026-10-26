#!/usr/bin/env python3
"""Checks apps/<id>.json files for the kia-apps index and reviews what each package does.

usage: validate.py [options] apps/<id>.json ...
       validate.py --inspect <package.zip>     review a local zip, no json needed

For every new or changed version (every version without --base) it downloads the zip from
GitHub Releases, checks its SHA-256, opens it, checks NEMESIS.data against the entry and
writes a review: what the package installs, what runs as root, and every script line that
touches the system. Errors exit 1. Flags never fail: they are for the owner's review.

  --base REF            versions identical to the ones in REF's copy aren't downloaded, and
                        retired apps (deprecated, withdrawn) can't gain new ones
  --cache DIR           review cache, DIR/<sha256>.json (publish keeps it on gh-pages)
  --local-zip [ID@VER=]PATH
                        use a local zip instead of downloading (plain PATH: the newest
                        version of the only app given); the SHA-256 is still checked
  --apps-dir DIR        where `requires` are looked up (default: the first file's dir)
  --comment FILE        write the review as a PR comment (markdown)
  --labels FILE         write the PR labels that apply, one per line
  --json FILE           write the full report as JSON

Stdlib only (Python 3.8+), so CI and developers can run it without installing anything.
APK package names come from `aapt dump badging` when the Android SDK is around, otherwise
from a small binary-XML parser.
"""
import argparse
import glob
import hashlib
import io
import json
import os
import re
import shlex
import struct
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = ROOT / "schema" / "app.schema.json"

MAX_ZIP = 64 << 20
MAX_UNZIPPED = 256 << 20   # zip bombs: nothing legitimate on a head unit is near this
MAX_ICON = 64 << 10
MAX_ICON_PX = 256
# bump when the review logic changes, so cached reviews are recomputed
REVIEW_VERSION = 1

RELEASE_URL = re.compile(
    r"^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/releases/download/[^/?#\s]+/[^/?#\s]+$")
LABELS = ("root", "system-writes", "needs-firmware-match")
MARKER = "<!-- kia-apps-review -->"


class Fail(Exception):
    pass


# ---------------------------------------------------------------- versions

def vkey(v):
    """'1.10' -> [1, 10]; trailing zeros dropped so 1.0 == 1."""
    parts = [int(p) for p in v.split(".")]
    while len(parts) > 1 and parts[-1] == 0:
        parts.pop()
    return parts


def vcmp(a, b):
    ka, kb = vkey(a), vkey(b)
    return (ka > kb) - (ka < kb)


# set on an app that is retired; entries are never deleted, so cars that have it can be told
RETIRED = ("withdrawn", "deprecated")
REQUIRE = re.compile(r"^([A-Za-z0-9]+(?:[._-][A-Za-z0-9]+)*)(?:>=([0-9]+(?:\.[0-9]+)*))?$")


# ---------------------------------------------------------------- JSON schema (the subset we use)

TYPES = {"string": str, "array": list, "object": dict, "boolean": bool}


def type_ok(v, t):
    if t == "integer":
        return isinstance(v, int) and not isinstance(v, bool)
    if t == "number":
        return isinstance(v, (int, float)) and not isinstance(v, bool)
    if t == "null":
        return v is None
    return isinstance(v, TYPES[t])


def check_schema(v, s, path="$"):
    t = s.get("type")
    if t and not type_ok(v, t):
        return ["%s: should be a %s" % (path, t)]
    errs = []
    if "enum" in s and v not in s["enum"]:
        errs.append("%s: %s isn't one of %s" % (path, json.dumps(v), ", ".join(s["enum"])))
    if isinstance(v, str):
        if len(v) < s.get("minLength", 0):
            errs.append("%s: too short" % path)
        if "maxLength" in s and len(v) > s["maxLength"]:
            errs.append("%s: longer than %d characters" % (path, s["maxLength"]))
        if "pattern" in s and not re.search(s["pattern"], v):
            errs.append("%s: %s doesn't match %s" % (path, json.dumps(v), s["pattern"]))
    if isinstance(v, list):
        if len(v) < s.get("minItems", 0):
            errs.append("%s: needs at least %d item(s)" % (path, s["minItems"]))
        if "maxItems" in s and len(v) > s["maxItems"]:
            errs.append("%s: more than %d items" % (path, s["maxItems"]))
        if s.get("uniqueItems") and len({json.dumps(x, sort_keys=True) for x in v}) != len(v):
            errs.append("%s: has duplicates" % path)
        if "items" in s:
            for i, x in enumerate(v):
                errs += check_schema(x, s["items"], "%s[%d]" % (path, i))
    if isinstance(v, dict):
        for k in s.get("required", []):
            if k not in v:
                errs.append("%s: missing %s" % (path, k))
        props = s.get("properties", {})
        for k, x in v.items():
            if k in props:
                errs += check_schema(x, props[k], "%s.%s" % (path, k))
            elif s.get("additionalProperties") is False:
                errs.append("%s: unknown field %s" % (path, k))
    return errs


# ---------------------------------------------------------------- downloads

class HttpsOnly(urllib.request.HTTPRedirectHandler):
    # GitHub redirects release assets to its CDN; never let that drop to plain http
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not newurl.startswith("https://"):
            raise Fail("redirected to a non-https URL: %s" % newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(url, limit):
    if not url.startswith("https://"):
        raise Fail("not an https URL: %s" % url)
    opener = urllib.request.build_opener(HttpsOnly)
    req = urllib.request.Request(url, headers={"User-Agent": "kia-apps-validate"})
    try:
        with opener.open(req, timeout=120) as r:
            n = r.headers.get("Content-Length")
            if n and n.isdigit() and int(n) > limit:
                raise Fail("%s is %s bytes, more than the %d allowed" % (url, n, limit))
            data = r.read(limit + 1)
    except (urllib.error.URLError, OSError) as e:
        raise Fail("download failed: %s: %s" % (url, getattr(e, "reason", e)))
    if len(data) > limit:
        raise Fail("%s is more than the %d bytes allowed" % (url, limit))
    return data


def png_size(data):
    if data[:8] != b"\x89PNG\r\n\x1a\n" or data[12:16] != b"IHDR":
        raise Fail("not a PNG")
    return struct.unpack(">II", data[16:24])


def check_icon(url, fetcher=fetch):
    data = fetcher(url, MAX_ICON)
    w, h = png_size(data)
    if w > MAX_ICON_PX or h > MAX_ICON_PX:
        raise Fail("icon is %dx%d, at most %dx%d" % (w, h, MAX_ICON_PX, MAX_ICON_PX))
    return data


# ---------------------------------------------------------------- NEMESIS.data

def parse_ini(text):
    """NEMESIS.data -> {section: {key: value}}, in file order. Keys are lowercased."""
    out, cur = {}, None
    for n, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if not s or s[0] in "#;":
            continue
        if s.startswith("[") and s.endswith("]"):
            name = s[1:-1].strip().lower()
            if name in out:
                raise Fail("NEMESIS.data:%d: section [%s] appears twice" % (n, name))
            cur = out[name] = {}
        elif "=" in s and cur is not None:
            k, v = s.split("=", 1)
            cur[k.strip().lower()] = v.strip()
        else:
            raise Fail("NEMESIS.data:%d: can't parse %r" % (n, s))
    return out


def numbered(ini, prefix):
    secs = [(int(k.split(".", 1)[1]), k) for k in ini if re.match(r"^%s\.\d+$" % prefix, k)]
    return [ini[k] for _, k in sorted(secs)]


# ---------------------------------------------------------------- APKs

def find_aapt():
    for var in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        sdk = os.environ.get(var)
        if not sdk:
            continue
        found = glob.glob(os.path.join(sdk, "build-tools", "*", "aapt"))

        def key(p):
            v = os.path.basename(os.path.dirname(p))
            return [int(x) if x.isdigit() else -1 for x in re.split(r"[.-]", v)]
        if found:
            return max(found, key=key)
    return None


def apk_info_aapt(aapt, apk):
    with tempfile.NamedTemporaryFile(suffix=".apk") as f:
        f.write(apk)
        f.flush()
        out = subprocess.run([aapt, "dump", "badging", f.name], stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, timeout=60).stdout.decode("utf-8", "replace")
    m = re.search(r"^package: name='([^']*)' versionCode='([^']*)'", out, re.M)
    if not m:
        return None
    return {"package": m.group(1), "version_code": int(m.group(2) or 0)}


def _len8(d, p):
    n = d[p]
    p += 1
    if n & 0x80:
        n = ((n & 0x7F) << 8) | d[p]
        p += 1
    return n, p


def _string_pool(d, pos):
    _, hsize, _, count, _, flags, start, _ = struct.unpack_from("<HHIIIIII", d, pos)
    offs = struct.unpack_from("<%dI" % count, d, pos + hsize)
    out = []
    for o in offs:
        p = pos + start + o
        if flags & 0x100:  # UTF-8: char count, then byte count
            _, p = _len8(d, p)
            n, p = _len8(d, p)
            out.append(d[p:p + n].decode("utf-8", "replace"))
        else:
            n = struct.unpack_from("<H", d, p)[0]
            p += 2
            if n & 0x8000:
                n = ((n & 0x7FFF) << 16) | struct.unpack_from("<H", d, p)[0]
                p += 2
            out.append(d[p:p + 2 * n].decode("utf-16-le", "replace"))
    return out


ATTR_VERSION_CODE = 0x0101021B


def parse_axml_manifest(d):
    """Binary AndroidManifest.xml -> {"package", "version_code"} from the <manifest> tag."""
    typ, hsize, _ = struct.unpack_from("<HHI", d, 0)
    if typ != 0x0003:
        raise Fail("AndroidManifest.xml isn't binary XML")
    strings, resids, pos = [], [], hsize
    while pos + 8 <= len(d):
        ctype, chsize, csize = struct.unpack_from("<HHI", d, pos)
        if csize < 8:
            break
        if ctype == 0x0001:
            strings = _string_pool(d, pos)
        elif ctype == 0x0180:
            resids = struct.unpack_from("<%dI" % ((csize - chsize) // 4), d, pos + chsize)
        elif ctype == 0x0102:
            _, name, astart, asize, acount = struct.unpack_from("<IIHHH", d, pos + chsize)
            if strings[name] != "manifest":
                raise Fail("AndroidManifest.xml doesn't start with <manifest>")
            out = {"package": None, "version_code": 0}
            for i in range(acount):
                ans, an, raw, _, _, dtype, data = struct.unpack_from(
                    "<IIIHBBI", d, pos + chsize + astart + i * asize)
                rid = resids[an] if an < len(resids) else 0
                aname = strings[an] if an < len(strings) else ""
                # obfuscated manifests may blank attribute names; the resource id still holds
                if rid == ATTR_VERSION_CODE or (not rid and aname == "versionCode"):
                    if dtype in (0x10, 0x11):
                        out["version_code"] = data - (1 << 32) if dtype == 0x10 and data >= 1 << 31 else data
                    elif raw != 0xFFFFFFFF:
                        out["version_code"] = int(strings[raw])
                elif aname == "package" and not rid and ans == 0xFFFFFFFF:
                    out["package"] = strings[raw] if raw != 0xFFFFFFFF else strings[data]
            return out
        pos += csize
    raise Fail("AndroidManifest.xml has no <manifest> element")


def apk_info(apk):
    aapt = find_aapt()
    if aapt:
        try:
            info = apk_info_aapt(aapt, apk)
            if info:
                return info
        except (OSError, subprocess.SubprocessError):
            pass
    try:
        with zipfile.ZipFile(io.BytesIO(apk)) as z:
            return parse_axml_manifest(z.read("AndroidManifest.xml"))
    except (zipfile.BadZipFile, KeyError, struct.error, IndexError, ValueError) as e:
        raise Fail("can't read the APK's manifest: %s" % e)


# ---------------------------------------------------------------- script review

# a write anywhere else is outside what a package should touch without saying so
SAFE_DIRS = ("/data/nemesis/", "/sdcard/", "/mnt/sdcard/", "/storage/", "/data/local/tmp/", "/tmp/")
SYSTEM_DIRS = ("/system", "/vendor", "/oem", "/firmware", "/persist", "/cache", "/data/dalvik-cache",
               "/data/system", "/data/app", "/data/misc", "/data/property")
APP_DATA = re.compile(r"^/data/(?:data|user(?:_de)?/\d+)/([^/\s\"']+)")
# command -> which arguments it writes: last, all, or all but the first (mode/owner)
WRITERS = {"cp": "last", "install": "last", "ln": "last", "mv": "all", "rm": "all",
           "rmdir": "all", "touch": "all", "mkdir": "all", "truncate": "all", "tee": "all",
           "restorecon": "all", "chmod": "skip1", "chown": "skip1", "chgrp": "skip1",
           "chcon": "skip1"}
PERMS = ("chmod", "chown", "chgrp", "chcon")
PREFIXES = {"if", "then", "else", "elif", "do", "while", "until", "!", "{", "time", "exec",
            "nohup", "command", "busybox", "toolbox", "toybox", "$"}
SEPARATORS = {";", "&&", "||", "|", "&", "(", ")", ";;", "|&"}
NET = {"curl", "wget", "nc", "netcat", "ftpget", "tftp", "telnet", "ssh", "scp"}

# rule id -> (counts as a system write, what it means)
RULES = {
    "remount": (True, "remounts a filesystem (usually /system read-write)"),
    "mount": (True, "mounts or unmounts a filesystem"),
    "system-path": (True, "writes under /system or another system location"),
    "other-path": (True, "writes outside NEMESIS, sdcard and its own app dirs"),
    "perms": (True, "chmod/chown outside its own dirs"),
    "dd": (True, "dd writes outside its own dirs"),
    "setprop-persist": (True, "sets a persistent system property"),
    "pm": (True, "disables, hides, clears or uninstalls other apps"),
    "reboot": (True, "reboots or shuts down the head unit"),
    "iptables": (True, "changes the firewall"),
    "app-data": (True, "touches another app's private data"),
    "block-dev": (True, "touches raw block devices"),
    "kmod": (True, "loads or unloads kernel modules"),
    "setprop": (False, "sets a runtime property (ctl.* starts and stops init services)"),
    "as-uid": (False, "runs a command as another uid"),
    "kill": (False, "stops other processes"),
    "network": (False, "downloads or connects out at runtime: nothing fetched is covered by the index's hash"),
    "settings": (False, "changes Android settings"),
    "nemesis-pkg": (False, "installs or removes NEMESIS packages"),
    "pm-install": (False, "installs APKs or changes app permissions"),
    "kernel": (False, "writes kernel tunables under /proc or /sys"),
    "net-config": (False, "changes network interfaces or routes"),
    "eval": (False, "runs dynamically built code"),
    "perms-unknown": (False, "chmod/chown on a path the review can't resolve"),
    "binary": (False, "native binary: not inspected"),
}

ASSIGN = re.compile(r"^\s*(?:export\s+|local\s+|readonly\s+)?([A-Za-z_]\w*)=(\S*)\s*(?:#.*)?$")


def strip_comment(line):
    q, prev, skip = None, " ", False
    for i, c in enumerate(line):
        if skip:
            skip = False
        elif c == "\\" and q != "'":
            skip = True
        elif q:
            if c == q:
                q = None
        elif c in "'\"":
            q = c
        elif c == "#" and (prev.isspace() or prev in ";&|()"):
            return line[:i]
        prev = c
    return line


def logical_lines(text):
    """(line number, text) with comments stripped, continuations joined, heredocs skipped."""
    out, buf, start, heredoc = [], "", 0, None
    for n, raw in enumerate(text.splitlines(), 1):
        if heredoc:
            if raw.strip() == heredoc:
                heredoc = None
            continue
        line = strip_comment(raw)
        if not buf:
            start = n
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        buf += line
        m = re.search(r"(?<!<)<<(?!<)-?\s*['\"]?(\w+)['\"]?", buf)
        if m:
            heredoc = m.group(1)
        if buf.strip():
            out.append((start, buf))
        buf = ""
    if buf.strip():
        out.append((start, buf))
    return out


def variables(lines):
    """Simple NAME=value assignments; a name assigned two different values is unknown."""
    seen = {}
    for _, line in lines:
        m = ASSIGN.match(line)
        if not m:
            continue
        name, v = m.groups()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
            v = v[1:-1]
        if "`" in v or "$(" in v or "'" in v or '"' in v:
            v = None
        seen[name] = v if seen.get(name, v) == v else None
    known = {k: v for k, v in seen.items() if v is not None}
    for _ in range(5):
        known = {k: expand(v, known) for k, v in known.items()}
    return known


def expand(s, known):
    def sub(m):
        name = m.group(1) or m.group(2)
        return known.get(name, m.group(0))
    return re.sub(r"\$\{([A-Za-z_]\w*)\}|\$([A-Za-z_]\w*)", sub, s)


def tokenize(line):
    lex = shlex.shlex(line, posix=True, punctuation_chars=True)
    lex.whitespace_split = True
    lex.commenters = ""
    try:
        return list(lex)
    except ValueError:
        return line.split()


def segments(tokens):
    cur, redirs = [], []
    it = iter(tokens)
    for t in it:
        if t in SEPARATORS:
            if cur or redirs:
                yield cur, redirs
            cur, redirs = [], []
        elif t in (">", ">>", ">|", "&>", "&>>"):
            redirs.append(next(it, ""))
        elif t in ("<", "<<", "<<-", "<<<", ">&", "<&", "<>"):
            next(it, None)  # the file or fd it reads from: not an argument
        else:
            cur.append(t)
    if cur or redirs:
        yield cur, redirs


def classify(path, own):
    """None if the write is fine, else a rule id."""
    if "$" in path or "`" in path:
        return "unknown"
    if not path.startswith("/"):
        return None  # relative: the service runs from its own dir
    if path.startswith("/dev/block"):
        return "block-dev"
    if path.startswith("/dev/"):
        return None
    if path.startswith(("/proc/", "/sys/")):
        return "kernel"
    m = APP_DATA.match(path)
    if m:
        return None if m.group(1) in own else "app-data"
    for d in SYSTEM_DIRS:
        if path == d or path.startswith(d + "/"):
            return "system-path"
    if path.startswith(SAFE_DIRS) or path.rstrip("/") + "/" in SAFE_DIRS:
        return None
    return "other-path"


def scan_command(words, redirs, own, hits, depth=0):
    while words and (words[0] in PREFIXES or re.match(r"^[A-Za-z_]\w*=", words[0])):
        words = words[1:]
    targets = list(redirs)
    for w in words:
        if "/dev/block" in w:
            hits.add("block-dev")
        m = APP_DATA.search(w)
        if m and m.group(1) not in own:
            hits.add("app-data")
    if not words:
        cmd, args = "", []
    else:
        cmd, args = os.path.basename(words[0]), words[1:]
    opts = [a for a in args if a.startswith("-")]
    plain = [a for a in args if not a.startswith("-")]

    if "remount" in args or any(a.startswith("remount,") or ",remount" in a for a in args):
        hits.add("remount")
    if cmd in ("mount", "umount") and args:
        hits.add("mount")
    if cmd == "dd":
        targets += [a[3:] for a in args if a.startswith("of=")]
    if cmd == "sed" and any(o.startswith("-i") for o in opts) and plain:
        targets.append(plain[-1])
    if cmd in WRITERS:
        how = WRITERS[cmd]
        paths = plain[-1:] if how == "last" else plain[1:] if how == "skip1" else plain
        for p in paths:
            r = classify(p, own)
            if r == "unknown":
                if cmd in PERMS:
                    hits.add("perms-unknown")
            elif r:
                hits.add("perms" if cmd in PERMS and r == "other-path" else r)
    if cmd == "setprop" and plain:
        p = plain[0]
        if p.startswith("persist."):
            hits.add("setprop-persist")
        elif p == "sys.powerctl":
            hits.add("reboot")
        else:
            hits.add("setprop")
    if cmd == "pm" and plain:
        if plain[0] in ("disable", "disable-user", "hide", "block", "uninstall", "clear", "unhide"):
            hits.add("pm")
        elif plain[0] in ("install", "grant", "revoke", "enable"):
            hits.add("pm-install")
    if cmd in ("reboot", "shutdown", "poweroff", "halt") or (cmd == "svc" and plain[:2] in (
            ["power", "reboot"], ["power", "shutdown"])):
        hits.add("reboot")
    if cmd in ("iptables", "ip6tables", "iptables-restore", "ip6tables-restore"):
        hits.add("iptables")
    if cmd in ("insmod", "rmmod", "modprobe"):
        hits.add("kmod")
    if cmd in ("kill", "killall", "pkill") or (cmd == "am" and plain[:1] in (["force-stop"], ["kill"])):
        hits.add("kill")
    if cmd in NET:
        hits.add("network")
    if cmd == "settings" and plain[:1] in (["put"], ["delete"]):
        hits.add("settings")
    if cmd == "nemesis" and plain[:1] in (["install"], ["uninstall"]):
        hits.add("nemesis-pkg")
    if cmd in ("ifconfig", "route") and len(plain) > 1 or (cmd == "ip" and len(plain) > 2 and plain[0] in (
            "route", "rule", "addr", "address", "link")):
        hits.add("net-config")
    if cmd == "eval":
        hits.add("eval")
    if cmd in ("su", "run-as") or (cmd == "nemesis" and plain[:1] == ["root"]):
        hits.add("as-uid")
    if cmd in ("sh", "bash", "su", "nemesis", "mksh") and "-c" in args and depth < 3:
        i = args.index("-c")
        if i + 1 < len(args):
            scan_line(args[i + 1], own, hits, depth + 1)
    for t in targets:
        r = classify(t, own)
        if r and r != "unknown":
            hits.add(r)


def scan_line(line, own, hits, depth=0):
    for words, redirs in segments(tokenize(line)):
        scan_command(words, redirs, own, hits, depth)


def scan_script(text, name, own=()):
    """Flags lines of a shell script: [{"file", "line", "text", "rules": [ids]}]."""
    lines = logical_lines(text)
    known = variables(lines)
    raw = text.splitlines()
    flags = []
    for n, line in lines:
        hits = set()
        scan_line(expand(line, known), set(own), hits)
        if hits:
            flags.append({"file": name, "line": n, "text": raw[n - 1].strip()[:200],
                          "rules": sorted(hits, key=list(RULES).index)})
    return flags


# ---------------------------------------------------------------- packages

def inspect_zip(data):
    """Zip bytes -> {"nemesis": {id, version}, "review", "flags", "paths"}; raises Fail."""
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise Fail("not a zip file")
    infos = [i for i in z.infolist() if not i.is_dir()]
    names = [i.filename for i in infos]
    for n in names:
        if n.startswith("/") or "\\" in n or ".." in n.split("/"):
            raise Fail("unsafe path in zip: %r" % n)
    if len(set(names)) != len(names):
        raise Fail("zip has duplicate entries")
    if sum(i.file_size for i in infos) > MAX_UNZIPPED:
        raise Fail("zip unpacks to more than %d bytes" % MAX_UNZIPPED)
    if "NEMESIS.data" not in names:
        nested = [n for n in names if n.endswith("/NEMESIS.data")]
        raise Fail("no NEMESIS.data at the root of the zip" +
                   (" (found %s: zip the package's contents, not its folder)" % nested[0] if nested else ""))
    try:
        ini = parse_ini(z.read("NEMESIS.data").decode("utf-8-sig"))
    except UnicodeDecodeError:
        raise Fail("NEMESIS.data isn't UTF-8")
    nem = ini.get("nemesis")
    if nem is None:
        raise Fail("NEMESIS.data has no [nemesis] section")
    for k in ("id", "version"):
        if not nem.get(k):
            raise Fail("NEMESIS.data has no %s" % k)
    types = [t.strip().lower() for t in nem.get("types", "").split(",") if t.strip()]
    warnings = []

    def need(sec, what):
        p = sec.get("path", "")
        if p not in names:
            raise Fail("NEMESIS.data %s path %r isn't in the zip" % (what, p))
        return p

    apps, own = [], set()
    for i, sec in enumerate(numbered(ini, "app")):
        p = need(sec, "app")
        if sec.get("kind", "apk") != "apk":
            warnings.append("[app.%d] kind=%s isn't apk" % (i, sec.get("kind")))
            continue
        info = apk_info(z.read(p))
        if sec.get("package") and sec["package"] != info["package"]:
            raise Fail("[app.%d] says package=%s but %s is %s" % (i, sec["package"], p, info["package"]))
        own.add(info["package"])
        apps.append({"package": info["package"], "version_code": info["version_code"]})

    services, scripts = [], set()
    for i, sec in enumerate(numbered(ini, "service")):
        p = need(sec, "service")
        name = sec.get("name") or "service.%d" % i
        uid = sec.get("uid") or "root"
        services.append({"name": name, "uid": uid, "mode": sec.get("mode", "")})
        if sec.get("kind", "sh") == "sh":
            scripts.add(p)

    if apps and "application" not in types:
        warnings.append("NEMESIS.data has apps but types doesn't include application")
    if services and "service" not in types:
        warnings.append("NEMESIS.data has services but types doesn't include service")
    known = re.compile(r"^(nemesis|app\.\d+|service\.\d+)$")
    for k in ini:
        if not known.match(k):
            warnings.append("NEMESIS.data has an unknown section [%s]" % k)

    execute = "execute" in types or any(s.get("type", "").lower() == "execute" for s in ini.values())

    flags = []
    for n in names:
        head = z.open(n).read(4)
        if n.endswith(".apk"):
            continue
        if head == b"\x7fELF":
            flags.append({"file": n, "line": 0, "text": "", "rules": ["binary"]})
        elif n in scripts or n.endswith(".sh") or head[:2] == b"#!":
            text = z.read(n).decode("utf-8", "replace")
            flags += scan_script(text, n, own)

    review = {
        "types": types,
        "apps": apps,
        "services": services,
        "root_services": [s["name"] for s in services if s["uid"] in ("root", "0")],
        "system_writes": any(RULES[r][0] for f in flags for r in f["rules"]),
        "execute": execute,
    }
    return {"nemesis": {"id": nem["id"], "version": nem["version"]}, "review": review,
            "flags": flags, "warnings": warnings}


def review_zip(data, sha256, cache=None):
    """inspect_zip with the cache keyed by sha256 (the zip's identity)."""
    if cache:
        p = Path(cache) / ("%s.json" % sha256)
        if p.exists():
            try:
                c = json.loads(p.read_text())
                if c.get("tool") == REVIEW_VERSION and c.get("sha256") == sha256:
                    return c
            except ValueError:
                pass
    if data is None:
        return None
    r = inspect_zip(data)
    r.update(tool=REVIEW_VERSION, sha256=sha256, size=len(data))
    if cache:
        Path(cache).mkdir(parents=True, exist_ok=True)
        (Path(cache) / ("%s.json" % sha256)).write_text(json.dumps(r, indent=1, sort_keys=True) + "\n")
    return r


# ---------------------------------------------------------------- apps

def load_schema():
    return json.loads(SCHEMA.read_text())


def git_show(ref, path):
    try:
        rel = os.path.relpath(os.path.abspath(path), git_toplevel(path))
        out = subprocess.run(["git", "show", "%s:%s" % (ref, rel)], cwd=os.path.dirname(os.path.abspath(path)),
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except OSError:
        return None
    return out.stdout.decode() if out.returncode == 0 else None


def git_toplevel(path):
    out = subprocess.run(["git", "rev-parse", "--show-toplevel"], cwd=os.path.dirname(os.path.abspath(path)),
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=True)
    return out.stdout.decode().strip()


def retired(doc):
    """"withdrawn" or "deprecated" if the app is retired, else None."""
    for k in RETIRED:
        if k in doc:
            return k
    return None


def load_entry(path):
    try:
        doc = json.loads(Path(path).read_text())
        return doc if isinstance(doc, dict) else None
    except (OSError, ValueError):
        return None


def check_retirement(doc, apps_dir, base_doc, rep):
    err, warn = rep["errors"].append, rep["warnings"].append
    for k in RETIRED:
        if k in doc and not doc[k].strip():
            err("%s needs a reason: say in plain words why the app is retired" % k)
    how = retired(doc)
    rb = doc.get("replaced_by")
    if rb is not None:
        if not how:
            err("replaced_by only goes with deprecated or withdrawn")
        elif rb == doc["id"]:
            err("replaced_by names the app itself")
        else:
            other = load_entry(apps_dir / ("%s.json" % rb))
            if other is None:
                err("replaced_by names %s, which isn't in the index (%s)" % (rb, apps_dir))
            elif retired(other):
                warn("replaced_by names %s, which is %s too" % (rb, retired(other)))
    if how:
        # an app still offered that needs this one can no longer be installed where it's missing
        for p in sorted(apps_dir.glob("*.json")):
            other = load_entry(p)
            if not other or other.get("id") == doc["id"] or retired(other):
                continue
            try:
                needs = other["versions"][0].get("requires", [])
            except (KeyError, IndexError, TypeError, AttributeError):
                continue
            if any(isinstance(r, str) and REQUIRE.match(r) and REQUIRE.match(r).group(1) == doc["id"] for r in needs):
                warn("%s requires this app, so cars without it can't install %s any more" % (other["id"], other["id"]))
    if base_doc is not None and retired(base_doc) and not how:
        warn("was %s: the store offers it again" % retired(base_doc))


def check_app(path, base=None, cache=None, local_zips=None, apps_dir=None, fetcher=fetch, icons=True):
    """One apps/<id>.json -> report dict. base: the old file's text, "" for a file that is new
    against the base, or None (no base: every version is checked, as new)."""
    path = Path(path)
    rep = {"file": str(path), "id": path.stem, "errors": [], "warnings": [], "versions": [], "app": None}
    err = rep["errors"].append
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, UnicodeDecodeError) as e:
        err("not valid JSON: %s" % e)
        return rep
    if path.suffix != ".json":
        err("app files are apps/<id>.json")
    errs = check_schema(doc, load_schema())
    if errs:
        rep["errors"] += errs
        return rep
    rep["app"] = doc
    if doc["id"] != path.stem:
        err("id %s doesn't match the file name %s" % (doc["id"], path.name))

    versions = [v["version"] for v in doc["versions"]]
    for a, b in zip(versions, versions[1:]):
        if vcmp(a, b) == 0:
            err("version %s is listed twice (%s and %s compare equal)" % (a, a, b))
        elif vcmp(a, b) < 0:
            err("versions must be newest first: %s is listed before %s" % (a, b))

    apps_dir = Path(apps_dir) if apps_dir else path.parent
    for v in doc["versions"]:
        fw = v["firmware"]
        if "*" in fw and len(fw) > 1:
            err("%s: firmware is either [\"*\"] or a list of exact firmware strings" % v["version"])
        for r in v.get("requires", []):
            rid, rver = REQUIRE.match(r).groups()
            if rid == doc["id"]:
                err("%s: requires itself" % v["version"])
                continue
            dep = apps_dir / ("%s.json" % rid)
            if not dep.exists():
                err("%s: requires %s, which isn't in %s" % (v["version"], rid, apps_dir))
                continue
            try:
                d = json.loads(dep.read_text())
                newest = d["versions"][0]["version"]
                if rver and vcmp(newest, rver) < 0:
                    rep["warnings"].append("%s: requires %s but its newest listed version is %s" % (
                        v["version"], r, newest))
                if retired(d):
                    rep["warnings"].append("%s: requires %s, which is %s: cars without it can't install this" % (
                        v["version"], rid, retired(d)))
            except (ValueError, KeyError, IndexError, TypeError):
                pass

    if icons and doc.get("icon"):
        try:
            check_icon(doc["icon"], fetcher)
        except Fail as e:
            err("icon: %s" % e)

    old, base_doc = {}, None
    if base:
        try:
            base_doc = json.loads(base)
            old = {v["version"]: v for v in base_doc.get("versions", [])}
        except (ValueError, AttributeError, TypeError):
            old, base_doc = {}, None
    rep["removed"] = [v for v in old if v not in versions]
    check_retirement(doc, apps_dir, base_doc if isinstance(base_doc, dict) else None, rep)

    for i, v in enumerate(doc["versions"]):
        ver = {"version": v["version"], "url": v["url"], "sha256": v["sha256"], "status": "new",
               "firmware": v["firmware"], "requires": v.get("requires", []), "errors": [], "warnings": []}
        rep["versions"].append(ver)
        verr = ver["errors"].append
        o = old.get(v["version"])
        if o:
            if o.get("url") == v["url"] and o.get("sha256") == v["sha256"]:
                ver["status"] = "unchanged"
            else:
                ver["status"] = "changed"
                ver["warnings"].append("version %s was already listed with a different zip: cars that "
                                       "installed the old one won't see this as an update" % v["version"])
        # a retired app keeps the versions cars may have, but gets no new ones
        if base is not None and retired(doc) and ver["status"] != "unchanged":
            verr("the app is %s: no new versions can be added to it" % retired(doc))
            continue
        if not RELEASE_URL.match(v["url"]):
            verr("url must be https://github.com/<owner>/<repo>/releases/download/<tag>/<file>")
            continue

        local = (local_zips or {}).get("%s@%s" % (doc["id"], v["version"]))
        if local is None and i == 0 and local_zips and "" in local_zips:
            local = local_zips[""]
        if ver["status"] == "unchanged" and local is None:
            r = review_zip(None, v["sha256"], cache)
            if r is None:
                continue  # unchanged and not cached: nothing to look at
        else:
            r = review_zip(None, v["sha256"], cache) if local is None else None
            if r is None:
                try:
                    data = Path(local).read_bytes() if local else fetcher(v["url"], MAX_ZIP)
                except (Fail, OSError) as e:
                    verr(str(e))
                    continue
                got = hashlib.sha256(data).hexdigest()
                if got != v["sha256"]:
                    verr("sha256 mismatch: the zip is %s, the entry says %s" % (got, v["sha256"]))
                    continue
                try:
                    r = review_zip(data, got, cache)
                except Fail as e:
                    verr(str(e))
                    continue
        ver["size"] = r["size"]
        ver["review"] = r["review"]
        ver["flags"] = r["flags"]
        ver["warnings"] += r.get("warnings", [])
        if r["nemesis"]["id"] != doc["id"]:
            verr("NEMESIS.data id is %s, not %s" % (r["nemesis"]["id"], doc["id"]))
        if r["nemesis"]["version"] != v["version"]:
            verr("NEMESIS.data version is %s, not %s" % (r["nemesis"]["version"], v["version"]))
        if r["review"]["execute"]:
            verr("type=execute (USB autorun) packages are refused by the store")
        if r["review"]["system_writes"] and v["firmware"] == ["*"]:
            verr("writes to the system but firmware is [\"*\"]: list the exact firmware it was made for")
    return rep


def ok(rep):
    return not rep["errors"] and not any(v["errors"] for v in rep["versions"])


def labels(reps):
    out = set()
    for rep in reps:
        for v in rep["versions"]:
            if v["status"] == "unchanged" or "review" not in v:
                continue
            if v["review"]["root_services"]:
                out.add("root")
            if v["review"]["system_writes"]:
                out.add("system-writes")
            if v["firmware"] != ["*"]:
                out.add("needs-firmware-match")
    return [l for l in LABELS if l in out]


# ---------------------------------------------------------------- the comment

def md(s):
    """Untrusted text into markdown: no formatting, links, html or @mentions."""
    s = re.sub(r"([\\`*_\[\]<>|~])", r"\\\1", str(s))
    return s.replace("@", "@\u200b").replace("\n", " ")


def code(s):
    s = str(s).replace("\n", " ")
    ticks = max([len(m) for m in re.findall(r"`+", s)] + [0]) + 1
    pad = " " if s.startswith("`") or s.endswith("`") else ""
    return "`" * ticks + pad + s + pad + "`" * ticks


def describe(v):
    r = v["review"]
    out = []
    for a in r["apps"]:
        out.append("- installs the app %s (versionCode %d)" % (code(a["package"]), a["version_code"]))
    for s in r["services"]:
        out.append("- runs the service %s as uid %s%s" % (code(s["name"]), code(s["uid"]),
                                                          ", mode " + code(s["mode"]) if s["mode"] else ""))
    if not r["apps"] and not r["services"]:
        out.append("- installs no apps or services")
    out.append("- runs as root: %s" % (", ".join(code(n) for n in r["root_services"]) or "nothing"))
    out.append("- writes to the system: **%s**" % ("yes" if r["system_writes"] else "no"))
    if r["execute"]:
        out.append("- **type=execute** (USB autorun): refused by the store")
    return out


def comment(reps, extra_errors=()):
    lines = [MARKER, "## kia-apps review", ""]
    good = all(ok(r) for r in reps) and not extra_errors
    lines.append("All checks passed." if good else "**Checks failed**: see the errors below.")
    for e in extra_errors:
        lines.append("- :x: %s" % md(e))
    for rep in reps:
        lines += ["", "### %s" % md(rep["id"]), ""]
        for e in rep["errors"]:
            lines.append("- :x: %s" % md(e))
        for w in rep["warnings"]:
            lines.append("- :warning: %s" % md(w))
        app = rep.get("app") or {}
        if app.get("withdrawn"):
            lines.append("- **withdrawn** (cars that have it are urged to remove it): %s" % md(app["withdrawn"]))
        if app.get("deprecated"):
            lines.append("- **deprecated** (no longer offered): %s" % md(app["deprecated"]))
        if app.get("replaced_by"):
            lines.append("- replaced by %s" % code(app["replaced_by"]))
        for r in rep.get("removed", []):
            lines.append("- removes version %s" % code(r))
        for v in rep["versions"]:
            if v["status"] == "unchanged" and not v["errors"]:
                lines.append("- %s unchanged" % code(v["version"]))
                continue
            lines += ["", "#### %s %s (%s)" % (md(rep["id"]), md(v["version"]), v["status"]), ""]
            fw = "any (`*`)" if v["firmware"] == ["*"] else ", ".join(code(f) for f in v["firmware"])
            lines.append("%s  " % code(v["url"]))
            if "size" in v:
                lines.append("%d bytes, sha256 %s matches  " % (v["size"], code(v["sha256"])))
            lines.append("firmware: %s  " % fw)
            if v["requires"]:
                lines.append("requires: %s  " % ", ".join(code(r) for r in v["requires"]))
            lines.append("")
            for e in v["errors"]:
                lines.append("- :x: %s" % md(e))
            for w in v["warnings"]:
                lines.append("- :warning: %s" % md(w))
            if "review" not in v:
                continue
            lines += describe(v)
            if v["flags"]:
                lines += ["", "<details open><summary>Flagged lines (for review; they don't fail the check)"
                          "</summary>", ""]
                for f in v["flags"]:
                    why = "; ".join(("**%s**" if RULES[r][0] else "%s") % RULES[r][1] for r in f["rules"])
                    where = "%s:%d" % (f["file"], f["line"]) if f["line"] else f["file"]
                    lines.append("- %s: %s" % (code(where), why))
                    if f["text"]:
                        lines.append("  %s" % code(f["text"]))
                lines += ["", "</details>"]
            else:
                lines += ["", "No flagged lines."]
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------- main

def main(argv=None):
    ap = argparse.ArgumentParser(description="Check apps/<id>.json files and review their packages.")
    ap.add_argument("files", nargs="*")
    ap.add_argument("--inspect", metavar="ZIP")
    ap.add_argument("--base")
    ap.add_argument("--cache")
    ap.add_argument("--local-zip", action="append", default=[])
    ap.add_argument("--apps-dir")
    ap.add_argument("--comment")
    ap.add_argument("--labels")
    ap.add_argument("--json")
    a = ap.parse_args(argv)

    if a.inspect:
        try:
            r = inspect_zip(Path(a.inspect).read_bytes())
        except (Fail, OSError) as e:
            print("error: %s" % e, file=sys.stderr)
            return 1
        r["sha256"] = hashlib.sha256(Path(a.inspect).read_bytes()).hexdigest()
        print(json.dumps(r, indent=1))
        return 0
    if not a.files:
        ap.error("no files")

    local = {}
    for s in a.local_zip:
        key, _, p = s.rpartition("=") if "=" in s else ("", "", s)
        local[key] = p
    if "" in local and len(a.files) != 1:
        ap.error("a plain --local-zip PATH needs exactly one file; use ID@VERSION=PATH")

    reps = []
    for f in a.files:
        base = None
        if a.base:
            base = git_show(a.base, f) or ""  # "": not in the base, so every version is new
        reps.append(check_app(f, base, a.cache, local, a.apps_dir))
    text = comment(reps)
    if a.comment:
        Path(a.comment).write_text(text)
    else:
        print(text)
    if a.labels:
        Path(a.labels).write_text("".join(l + "\n" for l in labels(reps)))
    if a.json:
        Path(a.json).write_text(json.dumps(reps, indent=1) + "\n")
    bad = [r["file"] for r in reps if not ok(r)]
    for b in bad:
        print("error: %s failed the checks" % b, file=sys.stderr)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
