"""apps/<id>.json checks: schema, versions, downloads, hashes, labels, the PR comment."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from helpers import Fetcher, entry, package, png, version, write

import validate


class Versions(unittest.TestCase):
    def test_compare(self):
        for a, b, want in [("1.10", "1.9", 1), ("1.0", "1", 0), ("1", "1.0.0", 0), ("1.1", "1.0.9", 1),
                           ("2", "10", -1), ("1.0.1", "1", 1), ("01.2", "1.2", 0)]:
            self.assertEqual(validate.vcmp(a, b), want, (a, b))
            self.assertEqual(validate.vcmp(b, a), -want, (b, a))


@mock.patch.object(validate, "find_aapt", lambda: None)
class Apps(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.zip = package(version="1.1")
        self.v = version("1.1", self.zip)
        self.fetch = Fetcher({self.v["url"]: self.zip})

    def tearDown(self):
        self.tmp.cleanup()

    def check(self, doc, name=None, **kw):
        kw.setdefault("fetcher", self.fetch)
        return validate.check_app(write(self.dir, doc, name), **kw)

    def errors(self, rep):
        return rep["errors"] + [e for v in rep["versions"] for e in v["errors"]]

    def test_good(self):
        rep = self.check(entry(versions=[self.v]))
        self.assertEqual(self.errors(rep), [])
        v = rep["versions"][0]
        self.assertEqual(v["size"], len(self.zip))
        self.assertEqual(v["review"]["root_services"], ["a"])
        self.assertEqual(validate.labels([rep]), ["root"])

    def test_schema_errors(self):
        bad = [
            (dict(category="games"), "isn't one of"),
            (dict(extra=1), "unknown field extra"),
            (dict(name=""), "too short"),
            (dict(versions=[]), "at least 1"),
            (dict(versions=[dict(self.v, sha256="TODO")]), "sha256"),
            (dict(versions=[dict(self.v, url="https://example.com/x.zip")]), "url"),
            (dict(versions=[dict(self.v, version="1.1-beta")]), "version"),
            (dict(versions=[dict(self.v, firmware=[])]), "firmware"),
            (dict(icon="http://x/y.png"), "icon"),
        ]
        for kw, msg in bad:
            rep = self.check(entry(**dict({"versions": [self.v]}, **kw)))
            self.assertTrue(any(msg in e for e in rep["errors"]), (kw, rep["errors"]))
            self.assertEqual(self.fetch.calls, [], "nothing is downloaded for a malformed file")

    def test_id_must_match_file_name(self):
        rep = self.check(entry(versions=[self.v]), name="other.pkg")
        self.assertIn("doesn't match the file name", rep["errors"][0])

    def test_version_order(self):
        z2 = package(version="1.2")
        v2 = version("1.2", z2)
        self.fetch.files[v2["url"]] = z2
        self.assertIn("newest first", self.check(entry(versions=[self.v, v2]))["errors"][0])
        self.assertEqual(self.errors(self.check(entry(versions=[v2, self.v]))), [])
        self.assertIn("listed twice", self.check(entry(versions=[self.v, dict(self.v, version="1.1.0")]))["errors"][0])

    def test_firmware_star_alone(self):
        rep = self.check(entry(versions=[dict(self.v, firmware=["*", "CVEV.X"])]))
        self.assertIn("either", rep["errors"][0])

    def test_hash_mismatch(self):
        rep = self.check(entry(versions=[dict(self.v, sha256="0" * 64)]))
        self.assertIn("sha256 mismatch: the zip is " + self.v["sha256"], self.errors(rep)[0])

    def test_id_and_version_must_match_zip(self):
        z = package(id="other.pkg", version="1.0")
        v = version("1.1", z)
        self.fetch.files[v["url"]] = z
        errs = self.errors(self.check(entry(versions=[v])))
        self.assertTrue(any("id is other.pkg" in e for e in errs))
        self.assertTrue(any("version is 1.0" in e for e in errs))

    def test_system_writes_need_exact_firmware(self):
        z = package(version="1.1", scripts={"svc/a.sh": "remount\nmount -o remount,rw /system\n"})
        v = version("1.1", z)
        self.fetch.files[v["url"]] = z
        self.assertIn("firmware is [\"*\"]", self.errors(self.check(entry(versions=[v])))[0])
        rep = self.check(entry(versions=[dict(v, firmware=["CVEV.USA.0000.V015.012.260507"])]))
        self.assertEqual(self.errors(rep), [])
        self.assertEqual(validate.labels([rep]), ["root", "system-writes", "needs-firmware-match"])

    def test_execute_is_refused(self):
        z = package(version="1.1", extra="\ntype=execute\n")
        v = version("1.1", z)
        self.fetch.files[v["url"]] = z
        self.assertIn("refused", self.errors(self.check(entry(versions=[v])))[0])

    def test_requires(self):
        rep = self.check(entry(versions=[dict(self.v, requires=["kia.menu>=1.1"])]))
        self.assertIn("requires kia.menu", rep["errors"][0])
        write(self.dir, entry("kia.menu", versions=[dict(self.v, version="1.0")]))
        rep = self.check(entry(versions=[dict(self.v, requires=["kia.menu>=1.1"])]))
        self.assertEqual(rep["errors"], [])
        self.assertIn("newest listed version is 1.0", rep["warnings"][0])

    def test_local_zip(self):
        p = self.dir / "local.zip"
        p.write_bytes(self.zip)
        rep = self.check(entry(versions=[self.v]), local_zips={"": str(p)}, fetcher=Fetcher())
        self.assertEqual(self.errors(rep), [])
        rep = self.check(entry(versions=[self.v]), local_zips={"test.pkg@1.1": str(p)}, fetcher=Fetcher())
        self.assertEqual(self.errors(rep), [])

    def test_base_skips_unchanged_versions(self):
        z0 = package(version="1.0")
        v0 = version("1.0", z0)
        base = json.dumps(entry(versions=[v0]))
        rep = self.check(entry(versions=[self.v, v0]), base=base)
        self.assertEqual([v["status"] for v in rep["versions"]], ["new", "unchanged"])
        self.assertEqual(self.fetch.calls, [self.v["url"]])
        changed = json.dumps(entry(versions=[dict(self.v, sha256="1" * 64)]))
        rep = self.check(entry(versions=[self.v]), base=changed)
        self.assertEqual(rep["versions"][0]["status"], "changed")
        self.assertIn("different zip", rep["versions"][0]["warnings"][0])

    def test_cache(self):
        cache = self.dir / "reviews"
        self.check(entry(versions=[self.v]), cache=cache)
        self.assertTrue((cache / (self.v["sha256"] + ".json")).exists())
        fetch = Fetcher()
        rep = self.check(entry(versions=[self.v]), cache=cache, fetcher=fetch)
        self.assertEqual(self.errors(rep), [])
        self.assertEqual(fetch.calls, [])

    def test_icon(self):
        icon = "https://raw.githubusercontent.com/o/r/v1/icon.png"
        for data, msg in [(png(64, 64), None), (png(300, 64), "300x64"), (b"GIF89a" + b"\0" * 30, "not a PNG")]:
            self.fetch.files[icon] = data
            rep = self.check(entry(versions=[self.v], icon=icon))
            if msg:
                self.assertIn(msg, rep["errors"][0])
            else:
                self.assertEqual(rep["errors"], [])

    def test_url_must_be_a_release(self):
        for url in ("https://github.com/o/r/archive/v1.zip", "https://raw.githubusercontent.com/o/r/x.zip"):
            rep = self.check(entry(versions=[dict(self.v, url=url)]))
            self.assertTrue(rep["errors"] or self.errors(rep))

    def test_comment(self):
        z = package(version="1.1", scripts={"svc/a.sh": "#!/system/bin/sh\nreboot\n"})
        v = version("1.1", z, firmware=["CVEV.X"])
        self.fetch.files[v["url"]] = z
        rep = self.check(entry(versions=[v], name="Evil `name` @someone [x](http://e)"))
        text = validate.comment([rep])
        self.assertTrue(text.startswith(validate.MARKER))
        self.assertIn("All checks passed", text)
        self.assertIn("svc/a.sh:2", text)
        self.assertIn("reboots or shuts down", text)
        self.assertIn("writes to the system: **yes**", text)
        bad = validate.comment([self.check(entry(versions=[dict(self.v, sha256="0" * 64)]))])
        self.assertIn("Checks failed", bad)
        self.assertNotIn("@someone", validate.md("@someone"))

    def test_retired_needs_a_reason(self):
        for k in ("deprecated", "withdrawn"):
            rep = self.check(entry(versions=[self.v], **{k: "  "}))
            self.assertIn("%s needs a reason" % k, rep["errors"][0])
            rep = self.check(entry(versions=[self.v], **{k: True}))
            self.assertIn("should be a string", rep["errors"][0])
            rep = self.check(entry(versions=[self.v], **{k: "Built into Tweaks now."}))
            self.assertEqual(self.errors(rep), [])
            self.assertIn("**%s**" % k, validate.comment([rep]))

    def test_replaced_by(self):
        rep = self.check(entry(versions=[self.v], deprecated="Old.", replaced_by="kia.new"))
        self.assertIn("replaced_by names kia.new, which isn't in the index", rep["errors"][0])
        write(self.dir, entry("kia.new", versions=[self.v]))
        rep = self.check(entry(versions=[self.v], deprecated="Old.", replaced_by="kia.new"))
        self.assertEqual(self.errors(rep), [])
        self.assertIn("replaced by `kia.new`", validate.comment([rep]))
        rep = self.check(entry(versions=[self.v], replaced_by="kia.new"))
        self.assertIn("only goes with deprecated or withdrawn", rep["errors"][0])
        rep = self.check(entry(versions=[self.v], deprecated="Old.", replaced_by="test.pkg"))
        self.assertIn("names the app itself", rep["errors"][0])
        write(self.dir, entry("kia.new", versions=[self.v], withdrawn="Unsafe."))
        rep = self.check(entry(versions=[self.v], deprecated="Old.", replaced_by="kia.new"))
        self.assertIn("withdrawn too", rep["warnings"][0])

    def test_no_new_versions_on_a_retired_app(self):
        z2 = package(version="1.2")
        v2 = version("1.2", z2)
        self.fetch.files[v2["url"]] = z2
        base = json.dumps(entry(versions=[self.v]))
        for k in ("deprecated", "withdrawn"):
            # retiring as it is: fine, and nothing is downloaded
            calls = len(self.fetch.calls)
            rep = self.check(entry(versions=[self.v], **{k: "Old."}), base=base)
            self.assertEqual(self.errors(rep), [])
            self.assertEqual(self.fetch.calls[calls:], [])
            rep = self.check(entry(versions=[v2, self.v], **{k: "Old."}), base=base)
            self.assertIn("no new versions", rep["versions"][0]["errors"][0])
            self.assertEqual(rep["versions"][1]["errors"], [])
            rep = self.check(entry(versions=[dict(self.v, sha256="1" * 64)], **{k: "Old."}), base=base)
            self.assertIn("no new versions", rep["versions"][0]["errors"][0])
        # a new file can't start out retired; without --base (publish) every version is checked
        rep = self.check(entry(versions=[self.v], deprecated="Old."), base="")
        self.assertIn("no new versions", rep["versions"][0]["errors"][0])
        self.assertEqual(self.errors(self.check(entry(versions=[self.v], deprecated="Old."))), [])
        # un-retiring is the owner's call, and the comment says so
        rep = self.check(entry(versions=[v2, self.v]), base=json.dumps(entry(versions=[self.v], deprecated="x")))
        self.assertEqual(self.errors(rep), [])
        self.assertIn("offers it again", rep["warnings"][0])

    def test_requiring_a_retired_app_warns(self):
        write(self.dir, entry("kia.menu", versions=[dict(self.v, version="1.0")], deprecated="Old."))
        rep = self.check(entry(versions=[dict(self.v, requires=["kia.menu"])]))
        self.assertEqual(self.errors(rep), [])
        self.assertIn("which is deprecated", rep["warnings"][0])
        rep = self.check(entry("kia.menu", versions=[self.v], deprecated="Old."))
        self.assertIn("test.pkg requires this app", rep["warnings"][0])


class Fetch(unittest.TestCase):
    def test_https_only(self):
        with self.assertRaises(validate.Fail):
            validate.fetch("http://github.com/x", 10)


class Cli(unittest.TestCase):
    @mock.patch.object(validate, "find_aapt", lambda: None)
    def test_main_with_local_zip(self):
        with tempfile.TemporaryDirectory() as d:
            z = package(version="1.1")
            (Path(d) / "p.zip").write_bytes(z)
            f = write(d, entry(versions=[version("1.1", z)]))
            out = Path(d) / "c.md"
            lab = Path(d) / "labels"
            self.assertEqual(validate.main([str(f), "--local-zip", str(Path(d) / "p.zip"),
                                            "--comment", str(out), "--labels", str(lab)]), 0)
            self.assertIn("runs as root", out.read_text())
            self.assertEqual(lab.read_text(), "root\n")


if __name__ == "__main__":
    unittest.main()
