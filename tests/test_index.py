"""index.json: build, sign/verify round trip, keygen, and the shared test vectors."""
import base64
import datetime
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from helpers import HERE, Fetcher, entry, package, png, version, write

import build_index
import sign_index
import validate

try:
    import cryptography  # noqa: F401
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False
needs_crypto = unittest.skipUnless(HAVE_CRYPTO, "needs the cryptography package")
VECTORS = HERE / "vectors"
NOW = datetime.datetime(2026, 10, 25, 18, 0, 0)


@mock.patch.object(validate, "find_aapt", lambda: None)
class Build(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = Path(self.tmp.name)
        self.apps, self.pages = d / "apps", d / "pages"
        self.apps.mkdir()
        self.pages.mkdir()
        z1, z2 = package("b.pkg", "1.0"), package("a.pkg", "2.0")
        self.icon = "https://raw.githubusercontent.com/o/a/v2/icon.png"
        v1, v2 = version("1.0", z1), version("2.0", z2, requires=["b.pkg>=1"], notes="n")
        write(self.apps, entry("b.pkg", versions=[v1]))
        write(self.apps, entry("a.pkg", versions=[v2], icon=self.icon, description="dé"))
        self.fetch = Fetcher({v1["url"]: z1, v2["url"]: z2, self.icon: png(32, 32)})

    def tearDown(self):
        self.tmp.cleanup()

    def build(self, **kw):
        return build_index.build(self.apps, self.pages, "test-key", NOW, fetcher=self.fetch, **kw)

    def test_first_needs_flag(self):
        with self.assertRaises(validate.Fail):
            self.build()
        self.assertEqual(self.build(first=True)["sequence"], 1)

    def test_index(self):
        idx = self.build(first=True)
        self.assertEqual(idx["format"], 1)
        self.assertEqual(idx["generated"], "2026-10-25T18:00:00Z")
        self.assertEqual(idx["expires"], "2027-01-23T18:00:00Z")
        self.assertEqual(idx["key_id"], "test-key")
        self.assertEqual([a["id"] for a in idx["apps"]], ["a.pkg", "b.pkg"])
        a = idx["apps"][0]
        self.assertEqual(a["icon"]["url"], "https://hazptr.github.io/kia-apps/icons/a.pkg.png")
        self.assertTrue((self.pages / "icons" / "a.pkg.png").exists())
        self.assertNotIn("icon", idx["apps"][1])
        self.assertEqual(idx["apps"][1]["description"], "")
        v = a["versions"][0]
        self.assertEqual(set(v), {"version", "url", "sha256", "size", "firmware", "requires", "notes", "review"})
        self.assertEqual(set(v["review"]), {"types", "apps", "services", "root_services", "system_writes", "execute", "hooks", "sh_entries", "tweaks", "root"})
        raw = (self.pages / "index.json").read_bytes()
        raw.decode("ascii")  # ASCII only
        self.assertEqual(json.loads(raw), idx)

    def test_sequence_and_cache(self):
        self.build(first=True)
        calls = len(self.fetch.calls)
        self.assertEqual(self.build()["sequence"], 2)
        # zips come from the review cache; only the icon is fetched again
        self.assertEqual(self.fetch.calls[calls:], [self.icon])
        self.assertEqual(self.build()["sequence"], 3)

    def test_broken_app_fails_the_build(self):
        doc = json.loads((self.apps / "b.pkg.json").read_text())
        doc["versions"][0]["sha256"] = "0" * 64
        write(self.apps, doc)
        with self.assertRaises(validate.Fail) as c:
            self.build(first=True)
        self.assertIn("sha256 mismatch", str(c.exception))
        self.assertFalse((self.pages / "index.json").exists())

    def test_retired_fields_are_published(self):
        doc = json.loads((self.apps / "b.pkg.json").read_text())
        doc.update(deprecated="Built into A now.", replaced_by="a.pkg")
        write(self.apps, doc)
        idx = self.build(first=True)
        a, b = idx["apps"]
        self.assertEqual((b["deprecated"], b["replaced_by"]), ("Built into A now.", "a.pkg"))
        self.assertNotIn("withdrawn", b)
        self.assertFalse({"deprecated", "withdrawn", "replaced_by"} & set(a))
        self.assertEqual(len(b["versions"]), 1, "a retired app keeps its versions")
        doc["withdrawn"] = "Unsafe."
        write(self.apps, doc)
        self.assertEqual(self.build()["apps"][1]["withdrawn"], "Unsafe.")

    def test_bad_replaced_by_fails_the_build(self):
        doc = json.loads((self.apps / "b.pkg.json").read_text())
        doc.update(deprecated="Old.", replaced_by="gone.pkg")
        write(self.apps, doc)
        with self.assertRaises(validate.Fail) as c:
            self.build(first=True)
        self.assertIn("replaced_by names gone.pkg", str(c.exception))

    def test_icon_outage_keeps_last_icon(self):
        self.build(first=True)
        del self.fetch.files[self.icon]
        idx = self.build()
        self.assertIn("icon", idx["apps"][0])


class Verify(unittest.TestCase):
    def test_vectors(self):
        pub = sign_index.public_key((VECTORS / "test-key.pub.pem").read_text())
        sig = (VECTORS / "index.json.sig").read_text()
        self.assertTrue(sign_index.verify((VECTORS / "index.json").read_bytes(), sig, pub))
        self.assertFalse(sign_index.verify((VECTORS / "index.tampered.json").read_bytes(), sig, pub))
        cases = json.loads((VECTORS / "vectors.json").read_text())
        for c in cases["cases"]:
            got = sign_index.verify((VECTORS / c["index"]).read_bytes(), (VECTORS / c["sig"]).read_text(), pub)
            self.assertEqual(got, c["valid"], c)

    def test_garbage_signatures(self):
        pub = sign_index.public_key((VECTORS / "test-key.pub.pem").read_text())
        data = (VECTORS / "index.json").read_bytes()
        for sig in ("", "!!!", base64.b64encode(b"\0" * 384).decode(), base64.b64encode(b"\xff" * 384).decode(),
                    base64.b64encode(b"\1" * 10).decode()):
            self.assertFalse(sign_index.verify(data, sig, pub), sig)

    def test_real_public_keys_parse(self):
        for p in (HERE.parent / "keys").glob("*.pub.pem"):
            n, e = sign_index.public_key(p.read_text())
            self.assertEqual(n.bit_length(), 3072, p)
            self.assertEqual(e, 65537)


@needs_crypto
class Sign(unittest.TestCase):
    def setUp(self):
        import keygen
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name)
        self.priv, self.pub, _ = keygen.keygen("test-a", self.d / "private", self.d / "keys")
        self.index = self.d / "index.json"
        self.index.write_bytes(b'{"format": 1, "sequence": 5, "key_id": "test-a", "apps": []}\n')

    def tearDown(self):
        self.tmp.cleanup()

    def sign(self, *extra):
        return sign_index.main([str(self.index), "--key", str(self.priv), "--keys-dir", str(self.d / "keys")]
                               + list(extra))

    def test_round_trip(self):
        self.assertEqual(self.sign(), 0)
        sig = (self.d / "index.json.sig").read_text()
        self.assertFalse(sig.endswith("\n"))
        self.assertEqual(len(base64.b64decode(sig)), 384)
        pub = sign_index.public_key(self.pub.read_text())
        self.assertTrue(sign_index.verify(self.index.read_bytes(), sig, pub))
        self.assertTrue(sign_index.verify(self.index.read_bytes(), sig + "\n", pub))
        self.assertEqual(sign_index.main([str(self.index), "--verify", "--keys-dir", str(self.d / "keys")]), 0)
        # any change to the bytes, even whitespace, breaks it
        self.index.write_bytes(self.index.read_bytes().replace(b": 5", b":  5"))
        self.assertFalse(sign_index.verify(self.index.read_bytes(), sig, pub))
        self.assertEqual(sign_index.main([str(self.index), "--verify", "--keys-dir", str(self.d / "keys")]), 1)

    def test_key_from_env(self):
        with mock.patch.dict(os.environ, {"SIGNING_KEY": self.priv.read_text()}):
            self.assertEqual(sign_index.main([str(self.index), "--key-env", "SIGNING_KEY",
                                              "--keys-dir", str(self.d / "keys")]), 0)
        with mock.patch.dict(os.environ, {"SIGNING_KEY": ""}):
            self.assertEqual(sign_index.main([str(self.index), "--key-env", "SIGNING_KEY",
                                              "--keys-dir", str(self.d / "keys")]), 1)

    def test_wrong_key_is_refused(self):
        import keygen
        other, _, _ = keygen.keygen("test-b", self.d / "private", self.d / "keys")
        self.assertEqual(sign_index.main([str(self.index), "--key", str(other),
                                          "--keys-dir", str(self.d / "keys")]), 1)
        self.assertFalse((self.d / "index.json.sig").exists())

    def test_other_key_doesnt_verify(self):
        import keygen
        self.sign()
        _, other, _ = keygen.keygen("test-b", self.d / "private", self.d / "keys")
        sig = (self.d / "index.json.sig").read_text()
        self.assertFalse(sign_index.verify(self.index.read_bytes(), sig, sign_index.public_key(other.read_text())))

    def test_keygen_files(self):
        import keygen
        self.assertEqual(stat.S_IMODE(self.priv.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.priv.parent.stat().st_mode), 0o700)
        self.assertIn(b"BEGIN PRIVATE KEY", self.priv.read_bytes())
        self.assertIn(b"BEGIN PUBLIC KEY", self.pub.read_bytes())
        with self.assertRaises(SystemExit):
            keygen.keygen("test-a", self.d / "private", self.d / "keys")


if __name__ == "__main__":
    unittest.main()
