# kia-apps: an app store for NEMESIS head units

Status: design, 2026-10-25. Target: the 2023 Kia EV6 head unit (Gen5W, Android 4.4.2,
`wp_daudioplus_cvev_us`, firmware `CVEV.USA.0000.V015.012.260507`) running
[NEMESIS](https://github.com/xwtk/hmg_nemesis), and other Gen5W units where packages allow it.

## Goals

- Anyone can publish a NEMESIS package by opening a PR that adds one file to the index repo.
- The repo owner reviews and merges; that merge is the only trust decision.
- On the car, an **App Store** app in All Menus lists the apps, installs, updates and removes
  them, with no ADB or USB stick.
- The car never installs anything the owner didn't merge, even if the network, GitHub's TLS,
  the sdcard or another app on the car is hostile.

Not goals: payments, ratings, user accounts, hosting the packages (developers host their own
zips on GitHub Releases), or protecting a car from its owner.

## Pieces

| Piece | Where | What |
|---|---|---|
| Index repo | `hazptr/kia-apps` (this repo) | `apps/<id>.json` per app, CI that checks every PR, and a publish job that builds and **signs** `index.json` |
| Published index | GitHub Pages, `https://hazptr.github.io/kia-apps/` | `index.json`, `index.json.sig`, icons |
| App Store app | `kia-store/app`, NEMESIS package `kia.store` | Browses the index, downloads zips, asks the helper to install |
| Install helper | `kia-store/helper`, a service in `kia.store` | Runs as root, re-verifies everything itself, runs `nemesis install` |

`kia.store` is itself listed in the index, so it updates the same way as everything else.

## Trust model

The index is signed with the **index signing key** (RSA-3072, `SHA256withRSA`, PKCS#1 v1.5).
Its public key is pinned in both the app and the helper. The private key exists only in the
repo's Actions secret `INDEX_SIGNING_KEY` and an offline copy of the owner's.

Each version in the index carries the zip's SHA-256 and size, so signing the index covers every
package it lists. Developers sign their APKs with their own keys as usual; the store doesn't
rely on that.

Why RSA/PKCS#1 v1.5 and not Ed25519: Android 4.4's `java.security` has no Ed25519, while
`SHA256withRSA` works on every Android version. `SHA256withECDSA` would also work, but RSA
keeps the verifier trivially portable to the helper and to Python.

What each attacker gets:

| Attacker | Can | Can't |
|---|---|---|
| Network / bad TLS (the car's 2014-era CA store may force a lenient TLS fallback) | Block updates; replay an **old** signed index | Forge an index or a zip (signature + SHA-256) |
| Replay of an old index | Nothing, as long as it's newer than the last one seen | Roll back: `sequence` must not decrease, and `expires` bounds staleness to 90 days |
| Another app on the car / the sdcard (world-writable to sdcard_rw apps) | Swap or delete files on the sdcard (downloads, the index copy, results, status): at worst a failed install or a misleading progress message | Ask the helper for anything: requests come only from the App Store app's provider, which answers only root, system and adb (App Store 1.0 took them from the sdcard; 1.1 ignores and deletes those). Get anything installed that the signed index doesn't list with that exact hash: the helper copies to private storage first, then verifies |
| A developer whose PR was merged | Whatever their package does, as root | Ship a different zip later: the hash is pinned; a new zip needs a new PR |
| Someone with write access to the repo but not the secret | Change `apps/` | Publish: only the publish job can sign, and only from `main` |

The owner's review is the real security boundary: a merged package with a root service owns
every car that installs it. CI exists to make that review fast and hard to get wrong (below).

### Key handling

- Generate with `tools/keygen.py` → `index-signing.pem` (private, never committed) and
  `keys/<key_id>.pub.pem` (committed). `key_id` names the key, e.g. `kia-apps-2026a`.
- The app and helper pin a **list** of accepted `{key_id, public key}`, so a key can be rotated
  by shipping a `kia.store` update that trusts the new key before the index switches over.
- Lost or leaked key: ship a `kia.store` update that drops it (the update itself must still be
  signed by a trusted key, so keep a second, offline key in the pinned list from day one).

## Index repo layout

```
apps/<id>.json            one per app, written by the developer (the PR)
keys/<key_id>.pub.pem     public signing keys
schema/app.schema.json    JSON Schema for apps/*.json
tools/validate.py         checks one or more apps/*.json (used by CI, runnable locally)
tools/build_index.py      apps/*.json + review data -> index.json
tools/sign_index.py       index.json -> index.json.sig
tools/keygen.py           new signing key
.github/workflows/check.yml     on pull_request
.github/workflows/publish.yml   on push to main, weekly schedule, workflow_dispatch
CONTRIBUTING.md           how to submit an app
```

### `apps/<id>.json` (what a developer writes)

```json
{
  "id": "ev6.fixes",
  "name": "EV6 fixes",
  "summary": "eth0 guard, Android Auto recovery and a Status app",
  "description": "Longer text, plain, shown on the app's page.",
  "author": "hazptr",
  "homepage": "https://github.com/hazptr/ev6-fixes",
  "category": "fixes",
  "icon": "https://raw.githubusercontent.com/hazptr/ev6-fixes/v1.4/status/icon.png",
  "versions": [
    {
      "version": "1.4",
      "url": "https://github.com/hazptr/ev6-fixes/releases/download/v1.4/ev6.fixes-v1.4.zip",
      "sha256": "…64 hex…",
      "firmware": ["CVEV.USA.0000.V015.012.260507"],
      "requires": ["kia.menu>=1.1"],
      "notes": "What changed."
    }
  ]
}
```

- `id` is the NEMESIS package id and must equal the filename and `NEMESIS.data`'s `id`.
- `versions` is newest first. Older versions may stay listed; the store installs the newest
  one that fits the car's firmware.
- `firmware` is a list of exact firmware strings, or `["*"]` for packages that only install
  ordinary apps or services. A package that writes `/system` must list exact firmware.
- `category`: one of `fixes`, `apps`, `projection`, `system`, `tools`, `fun`.
- `icon` optional: a PNG, at most 256x256, at most 64 KiB, `https` only.
- `deprecated`, `withdrawn`, `replaced_by` optional: retirement, below.

### Retiring an app

Entries are **never deleted**: a car that installed an app needs its entry to say it's gone and
offer its removal. An entry is retired instead, by the owner, in a PR:

- `"deprecated": "<plain reason>"`: no longer offered. The store shows it only to cars that
  have it, as "No longer offered" with the reason; no install, no update; Remove.
- `"withdrawn": "<plain reason>"`: pulled for safety. The same, plus a warning on the app's
  page and on the browse screen (when installed) urging removal.
- `"replaced_by": "<id>"`, with either: the store adds "Get <name> instead" when that app is
  in the index.

A retired entry keeps its versions (so the store can still describe what's installed) but
can't gain new ones. Un-retiring is a PR that drops the field.

Removal never depends on the index. The helper removes any package **it** installed, by its
own record in `state.json`, even when the entry has vanished from the index, the index has
expired (a car offline for more than 90 days) or there is no index at all: removing needs only
the driver's tap, not trust in the index. Installed packages the index doesn't list show in an
"Installed" section as "Not in the store", with Remove. The helper still never removes the
store itself, nor packages it didn't install (those were put there by the owner some other
way; NEMESIS Manager removes them).

Helpers before 1.1 kept no record. So, once, the first 1.1 helper seeds it: every installed
package whose id is in the verified, unexpired index (offered or retired), never `kia.store`,
and logs what it added (`state.json` then says `"seeded": true`). Until such an index is on the
sdcard it tries again; after the seed, removal never reads the index again.

### CI on a PR (`check.yml`)

The PR may change only files under `apps/` (one app per PR is the norm; several is allowed).
For each changed app, `validate.py`:

1. Validates against the schema; checks the `id` against the filename; checks the version
   strings are unique and newest first.
2. For each **new or changed** version: downloads `url` (must be `https://github.com/<owner>/<repo>/releases/download/…`,
   at most 64 MiB, following GitHub's redirect) and checks `sha256`.
3. Opens the zip: `NEMESIS.data` at the root, its `id` and `version` match the entry.
4. Inspects what the package does and writes a **review** record:
   - `types` from `NEMESIS.data`; every `[app.N]` (package name and versionCode, read from the
     APK with `aapt dump badging` or a Python AXML parser); every `[service.N]` with its `uid`
     and `mode`.
   - `root_services`: services with `uid=root` (or no uid).
   - `system_writes`: any script containing `remount`, `/system/`, `mount -o`, `dd `, `setprop persist.`,
     `pm disable`, `reboot`, `iptables`, `chmod`/`chown` outside its own dir, `/data/data/` of other apps,
     `/dev/block`.
   - `execute`: `type=execute` (USB autorun-style), which the store **refuses outright**.
   - Every flagged line, with file and line number.
5. Posts (or updates) one PR comment with the review: what the package installs, what runs as
   root, and every flagged line. It labels the PR `root`, `system-writes` and `needs-firmware-match`
   as they apply. `system_writes` with `firmware: ["*"]` is an error.
6. Retirement: a PR that deletes (or renames) an `apps/*.json` fails, pointing at
   `deprecated`. So do an empty `deprecated` or `withdrawn`, a `replaced_by` without either or
   naming an id missing from `apps/`, and a new or changed version on a retired entry.

Checks fail on anything malformed or mismatched. Flags don't fail the check: they're for the owner.

### Publishing (`publish.yml`)

On push to `main` (and weekly, so `expires` never lapses, and on manual dispatch):

1. Re-run the checks over every `apps/*.json` and compute the review records (cached by sha256
   in the `gh-pages` branch so unchanged zips aren't downloaded again).
2. `build_index.py`: read the currently published `index.json` from `gh-pages` and set
   `sequence` = old + 1; `generated` = now; `expires` = now + 90 days.
3. `sign_index.py` with `INDEX_SIGNING_KEY` → `index.json.sig`.
4. Commit `index.json`, `index.json.sig` and icons to `gh-pages`. GitHub Pages serves it.

### `index.json` (what the car reads)

```json
{
  "format": 1,
  "sequence": 42,
  "generated": "2026-10-25T18:00:00Z",
  "expires": "2027-01-23T18:00:00Z",
  "key_id": "kia-apps-2026a",
  "apps": [
    {
      "id": "ev6.fixes", "name": "…", "summary": "…", "description": "…", "author": "…",
      "homepage": "…", "category": "fixes",
      "icon": {"url": "https://hazptr.github.io/kia-apps/icons/ev6.fixes.png", "sha256": "…"},
      "deprecated": "…", "withdrawn": "…", "replaced_by": "…",   (only when set)
      "versions": [
        {
          "version": "1.4", "url": "…", "sha256": "…", "size": 123456,
          "firmware": ["CVEV.USA.0000.V015.012.260507"], "requires": ["kia.menu>=1.1"], "notes": "…",
          "review": {
            "types": ["application", "service"],
            "apps": [{"package": "dev.ev6fixes.status", "version_code": 12}],
            "services": [{"name": "eth0-guard", "uid": "root"}],
            "root_services": ["eth0-guard", "aa-recover", "status"],
            "system_writes": false,
            "execute": false
          }
        }
      ]
    }
  ]
}
```

`index.json.sig` is the base64 of the `SHA256withRSA` signature over the **exact bytes** of
`index.json` as served. Verifiers must check the bytes they have, never a re-serialization.

Version comparison everywhere: split on `.`, compare numerically part by part, with missing
parts counting as 0 (`1.10` > `1.9`, `1.0` == `1`).

## On the car: `kia.store`

### Firmware and installed state

- Firmware string: the system property that holds `CVEV.USA.0000.V015.012.260507` on this car
  (find the exact property; fall back to showing "unknown firmware" and treating only `["*"]`
  versions as compatible).
- Installed packages and versions: the helper writes `nemesis pkg-list` output to the status
  file (below) every time it runs a request, and every 15 s.

### The App Store app (`dev.kiastore`)

Built with kia-menu's `build-app.sh --ui` on `KiaPage` (Kia's colours, Mobis font, day/night,
split-screen aware, slim title row). Shows up in All Menus via `MenuContract`.

- **Browse**: a grid/list of apps with icon, name, summary, an "Installed 1.3 / Update to 1.4"
  state, and category filter chips. Incompatible firmware greys the install button with a reason.
- **Retired apps** (`deprecated`, `withdrawn`) show only when installed, with Remove (and "Get
  <replacement> instead"); never Install or Update. A withdrawn app that's installed gets a
  warning at the top of the browse screen. **Installed**: packages the helper installed that
  the index doesn't list (or all of them, with no usable index), as "Not in the store", with
  Remove.
- **App page**: description, author, homepage (as text), version notes, and the review spelled
  out in plain words: "Installs the app Status", "Runs 3 services as root", "Writes to /system
  (firmware-locked)". Root and `/system` items get a confirmation step on install.
- **Install / Update / Remove**, with progress (download %, verifying, installing) and the
  helper's result or error message. `requires` is resolved first: missing requirements are
  offered as part of the same install, in dependency order.
- **Updates (n)**: a tab, shown when n > 0 (and counted in the header), listing every installed,
  non-retired app with a newer version for this firmware: installed → new version and the
  notes' first line, with Update per row. **Update all** is one plan with one confirmation
  (the order, and root or `/system` risk): requirements before what needs them, missing
  requirements installed first, the App Store itself last. The updates run one at a time with
  progress on each row; the first failure stops the plan, says which app, and leaves the rest
  untouched.
- **Expired index** (offline more than 90 days): the list still shows, with "The app list is
  out of date: connect to the internet to refresh it"; Install, Update and Update all are off
  (the helper refuses an expired index anyway). Remove still works.
- A day/night switch recreates the screen; the open page, tab and confirmation are kept.
- **Refresh**: fetch the index from Pages. Never accept an index whose signature fails, whose
  `sequence` is lower than the last accepted one, or that has expired; say which.
- Remembers the last accepted index in app storage and **also** in `/sdcard/kia-store/` (app
  data is wiped on every NEMESIS update, as kia-menu found).

Networking on Android 4.4: force TLS 1.2 on `HttpsURLConnection` (it's off by default on API
16-19 clients). The car's root CA store may not trust GitHub's current chains; bundle the roots
that `hazptr.github.io`, `github.com` and `objects.githubusercontent.com` chain to, and use
them in addition to the system's. Security never depends on TLS, only on the signature and
hashes, so if a host can't be validated, fail with a clear message rather than disable checking.

### Requests: app → helper

The app can't run `nemesis install` (it needs root), so it asks the helper. Nothing privileged
happens without the driver's knowledge, so a request has to come from the app, after the
driver's tap and confirmation, and from nowhere else. The sdcard can't carry that: any app with
sdcard access can write there. So requests go the way kia-tweaks hands its switches to tweaksd:

- The app keeps the requests the driver confirmed in its private storage
  (`files/requests/<time>-<uuid>.json`) and serves them, read-only, through a content provider:
  `content://dev.kiastore.requests/pending`, rows `(uuid, op, id, version)`. The provider
  answers only uid 0 (the helper), 1000 (system), 2000 (adb) and the app itself; any other app
  gets nothing, and nothing can be written through it (insert, update and delete do nothing).
  Android also refuses `content query` from app uids outright.
- The helper reads it with the stock `content query`, as root. That starts a VM (about 0.7 s of
  CPU here), so it reads only while the app's process exists: every 3 s while the app is in
  the foreground, right after it leaves or (re)starts, and every 15 s in the background.
- Each request runs once: the helper adds its uuid to `done` in its private `state.json`
  (the last 200) **before** acting on it, and skips any uuid listed there, even if the
  provider still shows it. The app drops a request as soon as it sees a result for it, when it
  gives up on it, and (the provider's `onCreate`) when its process starts, so a request nobody
  is watching never runs later.
- `/sdcard/kia-store/requests/` is App Store 1.0's channel. It is never read: the app and the
  helper delete what's there (the helper logs the names).

Everything else between them is on the sdcard, and none of it is trusted for anything
privileged:

```
/sdcard/kia-store/index.json, index.json.sig   the index the app accepted (helper re-checks it)
/sdcard/kia-store/downloads/<id>-<version>.zip  (helper copies it, then checks it against the index)
/sdcard/kia-store/results/<uuid>.json           helper → app: {"state": "working" | "ok" | "failed",
                                                  "step": "verifying", "message": "…", "log": "…"}
/sdcard/kia-store/status.json                   helper → app: heartbeat + `nemesis pkg-list` +
                                                firmware + "store_installed": the ids it installed
```

The app polls `results/` and the heartbeat (and says so plainly if the helper isn't running).
Results and status are only shown to the driver; another app could fake them, which can
mislead the screen but not make the helper do anything.

### The helper

A NEMESIS service in `kia.store` (`uid=root`, `mode=restart`). Its shell script launches a small
Java program as root (with `dalvikvm`), because verifying RSA signatures in `sh` isn't possible
here. It runs a private copy of `helper.jar` and exits (so svcmgr restarts it) whenever the
package's `helper.jar` differs from that copy: an update can land while the service starts, and
old code must not keep running after a fix. For each new request from the provider:

1. Record its uuid as done, then write `results/<uuid>.json` as `working`.
2. For install: copy `index.json` and `.sig` into private storage, `/data/nemesis/kia-store/`,
   and verify the signature against the **helper's own** pinned keys, the `sequence` against
   its own last-accepted sequence (stored in `/data/nemesis/kia-store/state.json`), and `expires`.
3. For install: find `id` + `version` in the index; refuse retired apps and `execute`; check firmware
   compatibility. Copy `downloads/<id>-<version>.zip` (a path the helper builds itself) into
   private storage, then check size and SHA-256 **of the copy**, then open it and check
   `NEMESIS.data`'s `id` and `version`.
4. Run `nemesis install --update <private copy>` (or `nemesis uninstall <id>`, only for ids
   the helper's own record in `state.json` says it installed, never `kia.store`, and without
   reading the index). Capture its output into the result.
5. Write the result, add or drop the id in `state.json`'s record, and refresh `status.json`.
   Delete the private zip copy.

The helper takes only "which operation, id and version" from the app, and only through the
provider; every check is repeated against its own pinned keys and its own copy of the bytes.

## Seed content

`apps/kia.menu.json`, `apps/ev6.fixes.json` and `apps/kia.store.json`, filled in once those
repos have CI-built releases (their release zips' SHA-256 come from the releases, not local
builds).

## Testing on the car

- Unit tests for the Python tools (schema, versions, review flags, index build, sign/verify
  round trip) and for the Java verifier (the same test vectors on both sides).
- An index served from a local file for development: the app and helper accept a debug index
  location only when a file `/data/nemesis/kia-store/debug-index` exists (root-only to create),
  and still verify it with a separate **test key** that is pinned only in debug builds.
- End-to-end on the car over ADB: install, update, remove, refusal of a tampered zip, of a bad
  signature and of a rolled-back sequence.
