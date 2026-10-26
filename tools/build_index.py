#!/usr/bin/env python3
"""Builds index.json from apps/*.json, for the car.

usage: build_index.py --pages <dir> --key-id <id> [--apps apps] [--first] [--now <ISO time>]
                      [--base-url https://hazptr.github.io/kia-apps/]

<dir> is a checkout of the gh-pages branch. Reads its index.json for the last sequence
(--first when there is none yet), reuses its reviews/<sha256>.json so unchanged zips aren't
downloaded again, and writes back index.json, icons/<id>.png and new reviews. Any app that
fails the checks fails the build: nothing is published until it's fixed.

Sign the result with sign_index.py; the index is only valid together with its .sig.
"""
import argparse
import datetime
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import validate  # noqa: E402

FORMAT = 1
LIFETIME = datetime.timedelta(days=90)
BASE_URL = "https://hazptr.github.io/kia-apps/"


def iso(t):
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def previous_sequence(pages, first):
    p = Path(pages) / "index.json"
    if not p.exists():
        if not first:
            raise validate.Fail("%s doesn't exist; pass --first for the very first index" % p)
        return 0
    try:
        seq = json.loads(p.read_text())["sequence"]
    except (ValueError, KeyError, TypeError):
        raise validate.Fail("can't read the sequence from %s" % p)
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
        raise validate.Fail("bad sequence in %s" % p)
    return seq


def icon(app, pages, base_url, fetcher):
    """Copies the app's icon into icons/<id>.png; keeps the last good one if the URL breaks."""
    out = Path(pages) / "icons" / (app["id"] + ".png")
    data = None
    try:
        data = validate.check_icon(app["icon"], fetcher)
    except validate.Fail as e:
        print("warning: %s icon: %s" % (app["id"], e), file=sys.stderr)
        if out.exists():
            data = out.read_bytes()
    if data is None:
        return None
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(data)
    return {"url": base_url + "icons/" + out.name, "sha256": hashlib.sha256(data).hexdigest()}


def build(apps_dir, pages, key_id, now, first=False, base_url=BASE_URL, fetcher=validate.fetch):
    seq = previous_sequence(pages, first) + 1
    cache = Path(pages) / "reviews"
    files = sorted(Path(apps_dir).glob("*.json"))
    reps = [validate.check_app(f, None, cache, None, apps_dir, fetcher, icons=False) for f in files]
    bad = [r for r in reps if not validate.ok(r)]
    if bad:
        msgs = []
        for r in bad:
            msgs += ["%s: %s" % (r["file"], e) for e in r["errors"]]
            msgs += ["%s %s: %s" % (r["file"], v["version"], e) for v in r["versions"] for e in v["errors"]]
        raise validate.Fail("\n".join(msgs))

    apps, icons = [], set()
    for r in sorted(reps, key=lambda r: r["app"]["id"]):
        a = r["app"]
        entry = {k: a.get(k, "") for k in ("id", "name", "summary", "description", "author",
                                           "homepage", "category")}
        if a.get("icon"):
            ic = icon(a, pages, base_url, fetcher)
            if ic:
                entry["icon"] = ic
                icons.add(a["id"] + ".png")
        # retired apps stay listed, so cars that have one can show why and offer its removal
        for k in ("deprecated", "withdrawn", "replaced_by"):
            if k in a:
                entry[k] = a[k]
        entry["versions"] = []
        for v, rv in zip(a["versions"], r["versions"]):
            entry["versions"].append({
                "version": v["version"], "url": v["url"], "sha256": v["sha256"], "size": rv["size"],
                "firmware": v["firmware"], "requires": v.get("requires", []), "notes": v.get("notes", ""),
                "review": rv["review"],
            })
        apps.append(entry)

    # icons of apps that left the index
    for p in (Path(pages) / "icons").glob("*.png"):
        if p.name not in icons:
            p.unlink()

    index = {"format": FORMAT, "sequence": seq, "generated": iso(now), "expires": iso(now + LIFETIME),
             "key_id": key_id, "apps": apps}
    # ASCII-only so every JSON reader on the car sees the same bytes the same way
    data = (json.dumps(index, indent=2, ensure_ascii=True) + "\n").encode("ascii")
    (Path(pages) / "index.json").write_bytes(data)
    return index


def main(argv=None):
    ap = argparse.ArgumentParser(description="Build index.json from apps/*.json.")
    ap.add_argument("--apps", default=str(Path(__file__).resolve().parent.parent / "apps"))
    ap.add_argument("--pages", required=True)
    ap.add_argument("--key-id", required=True)
    ap.add_argument("--base-url", default=BASE_URL)
    ap.add_argument("--first", action="store_true")
    ap.add_argument("--now", help="build time, e.g. 2026-10-25T18:00:00Z (default: now)")
    a = ap.parse_args(argv)
    if a.now:
        now = datetime.datetime.strptime(a.now, "%Y-%m-%dT%H:%M:%SZ")
    else:
        now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None, microsecond=0)
    base = a.base_url if a.base_url.endswith("/") else a.base_url + "/"
    try:
        index = build(a.apps, a.pages, a.key_id, now, a.first, base)
    except validate.Fail as e:
        print("error: %s" % e, file=sys.stderr)
        return 1
    print("index.json: sequence %d, %d app(s), expires %s" % (
        index["sequence"], len(index["apps"]), index["expires"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
