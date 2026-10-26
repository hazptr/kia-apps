# Submitting an app

An app in the store is one file, `apps/<id>.json`, added by a pull request. The store never
hosts packages: you publish your NEMESIS zip as a GitHub release asset, and the entry pins
its SHA-256. Once the PR is merged, the next publish puts it in the signed index and every
car running the App Store can install it.

## 1. Build and release the package

- The zip is an ordinary NEMESIS package: `NEMESIS.data` at the **root** of the zip (not in a
  folder), plus the files it points to.
- `NEMESIS.data`'s `id` is your app's id (e.g. `ev6.fixes`) and its `version` is the version
  you list (numbers and dots only: `1.4`, `2.0.1`).
- `type=execute` (USB autorun) packages are refused: the store only installs.
- Publish it as a release asset: `https://github.com/<you>/<repo>/releases/download/<tag>/<file>.zip`.
  At most 64 MiB. Don't replace the asset later: cars check the hash, so a changed zip needs
  a new version and a new PR. Building releases in CI (from a tag) makes this easy to keep.

Get the hash of the exact file you uploaded:

```sh
curl -sL -o pkg.zip https://github.com/<you>/<repo>/releases/download/v1.0/<file>.zip
sha256sum pkg.zip          # macOS: shasum -a 256 pkg.zip
```

## 2. Write `apps/<id>.json`

```json
{
  "id": "kia.tweaks",
  "name": "Tweaks",
  "summary": "Small fixes, each with an on/off switch",
  "description": "Turn on fixes like automatic daylight saving time and skipping the start-up screen.",
  "author": "hazptr",
  "homepage": "https://github.com/hazptr/kia-tweaks",
  "category": "fixes",
  "icon": "https://raw.githubusercontent.com/hazptr/kia-tweaks/<commit>/icon.png",
  "versions": [
    {
      "version": "1.0",
      "url": "https://github.com/hazptr/kia-tweaks/releases/download/v1.0/kia.tweaks-v1.0.zip",
      "sha256": "<64 hex digits>",
      "firmware": ["CVEV.USA.0000.V015.012.260507"],
      "requires": ["kia.menu>=1.1"],
      "notes": "What changed."
    }
  ]
}
```

- `id`: the NEMESIS package id; the file must be named `<id>.json`.
- `category`: one of `fixes`, `apps`, `projection`, `system`, `tools`, `fun`.
- `summary` and `description` are for drivers, not developers: say what the app does for them, in
  plain words, a short phrase and one sentence. Leave out how it works; the store already shows
  what a package installs and changes (apps, root services, `/system` writes) from the review.
- `description`, `homepage`, `icon` are optional. Pin `icon` to a commit or tag so it can't change. The icon is a PNG of at most 256x256 and
  64 KiB, over https.
- `versions`: newest first. You may keep older versions listed; the store installs the newest
  one that fits the car's firmware. Every version needs `version`, `url`, `sha256` and
  `firmware`; `requires` and `notes` are optional.
- `firmware`: `["*"]` if the package only installs ordinary apps and services. If it changes
  `/system` (or anything else the review flags as a system write), list the exact firmware
  strings it was made and tested for.
- `requires`: other apps in the store, optionally with a minimum version (`id>=1.1`). The store
  installs them first.

The full schema is [schema/app.schema.json](schema/app.schema.json).

## 3. Check it locally

```sh
python3 tools/validate.py apps/<id>.json
python3 tools/validate.py apps/<id>.json --local-zip dist/pkg.zip   # before uploading
python3 tools/validate.py --inspect dist/pkg.zip                    # just the review
```

Python 3.8+, nothing to install. It prints the same review CI will post.

## 4. Open the PR

Change only files under `apps/` (one app per PR is easiest to review). CI downloads every new
or changed version, checks the hash and `NEMESIS.data`, and posts a review comment:

- what the package installs: apps (package and versionCode) and services (uid and mode);
- what runs as **root**;
- whether it **writes to the system**, and every flagged script line with its file and line
  number. Flags never fail the check; they tell the reviewer where to look.

Labels: `root` (a service runs as root), `system-writes`, and `needs-firmware-match` (a version
lists exact firmware, so the reviewer checks the strings are right).

The check fails on anything malformed or mismatched: bad JSON or schema, an id that doesn't
match the file name or the zip, a hash mismatch, versions out of order, a missing
`requires` target, `type=execute`, system writes with `firmware: ["*"]`, or a deleted
`apps/*.json` (see [Retiring an app](#retiring-an-app)).

The owner reads the review and the scripts and merges or doesn't. A package with a root
service controls every car that installs it, so expect questions about anything flagged.

## Updates

Add the new version at the top of `versions` in a new PR (keep or drop the old ones). Same
checks, same review.

## Retiring an app

Entries are never deleted: a car that installed an app needs its entry to tell the driver it's
gone and to offer its removal. A PR that deletes (or renames) an `apps/*.json` fails the check.
The owner retires an app with a PR that keeps the file and sets:

```json
  "deprecated": "Built into Tweaks now.",
  "replaced_by": "kia.tweaks",
```

- `deprecated`: why, in plain words for drivers. It can't be empty. The store stops offering
  the app (no install, no update) and shows it, only to cars that have it, as "No longer
  offered" with this reason and a Remove button.
- `replaced_by` (optional): the id of another app in the index, which the store offers as
  "Get <name> instead". It must exist in `apps/`.
- `withdrawn`: for an app pulled for safety, with the reason. Everything `deprecated` does, plus
  a warning on the store's front page, on cars that have it, urging its removal.

Leave `versions` as they are: a retired entry can't gain new versions or new zips (the check
fails). To offer an app again, drop `deprecated`/`withdrawn` in a PR; the review says so.
