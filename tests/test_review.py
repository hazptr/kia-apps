"""Package inspection: NEMESIS.data, APKs, and the script flags the owner reviews."""
import unittest
from unittest import mock

from helpers import FIXTURES, apk, axml, make_zip, nemesis_data, package

import validate


def flags(text, own=()):
    return {f["line"]: f["rules"] for f in validate.scan_script(text, "s.sh", own)}


def script(*lines):
    return "#!/system/bin/sh\n" + "\n".join(lines) + "\n"


class Scripts(unittest.TestCase):
    def test_reads_of_system_are_not_writes(self):
        f = flags(script(
            "export PATH=/data/nemesis/bin:/sbin:/vendor/bin:/system/sbin:/system/bin:/system/xbin",
            "/system/xbin/nemesis pkg-list",
            "cat /system/build.prop | grep ro.build",
            "cp /system/etc/hosts /data/nemesis/me/hosts",
            "ls /system/app > /data/nemesis/me/apps.txt",
        ))
        self.assertEqual(f, {})

    def test_spec_list(self):
        f = flags(script(
            "mount -o remount,rw /system",       # 2
            "dd if=/sdcard/x.img of=/dev/block/mmcblk0p5",
            "setprop persist.sys.foo 1",
            "pm disable com.hyundai.foo",
            "reboot",
            "iptables -A INPUT -j DROP",
            "chmod 777 /data/local.prop",
            "rm -rf /data/data/com.other.app/cache",
            "cat /dev/block/by-name/system > /sdcard/sys.img",
            "echo x > /system/etc/hosts",
        ))
        self.assertEqual(f[2], ["remount", "mount"])
        self.assertIn("block-dev", f[3])
        self.assertEqual(f[4], ["setprop-persist"])
        self.assertEqual(f[5], ["pm"])
        self.assertEqual(f[6], ["reboot"])
        self.assertEqual(f[7], ["iptables"])
        self.assertEqual(f[8], ["perms"])
        self.assertEqual(f[9], ["app-data"])
        self.assertEqual(f[10], ["block-dev"])
        self.assertEqual(f[11], ["system-path"])

    def test_variables_are_followed(self):
        f = flags(script("APP=/system/app", "D=$APP/x", "chmod 644 ${D}.apk", "cp a $APP/", "cp $APP/a b"))
        self.assertEqual(f, {4: ["system-path"], 5: ["system-path"]})

    def test_variable_with_two_values_is_unknown(self):
        f = flags(script("D=/system", "D=/sdcard", "chmod 644 $D/x", "cp a $D/x"))
        self.assertEqual(f, {4: ["perms-unknown"]})

    def test_own_dirs_are_fine(self):
        f = flags(script("DIR=/data/nemesis/status", "mkdir -p $DIR && chmod 755 $DIR",
                         "chmod 644 relative.txt", "chown 1000 /data/data/dev.test/files/x",
                         "echo hi >> /sdcard/log.txt 2>&1", "cmd > /dev/null"), own={"dev.test"})
        self.assertEqual(f, {})

    def test_words_in_strings_and_comments_dont_count(self):
        f = flags(script('echo "done - reboot to load it"', "# reboot here", 'log "remount rw failed"',
                         "x=1 # setprop persist.x 1", 'fail "launcher on /system isn\'t stock"'))
        self.assertEqual(f, {})

    def test_hash_inside_quotes_isnt_a_comment(self):
        self.assertEqual(flags(script('echo "a \\" # b"; reboot', "echo ${#x} 'it''s # x'; reboot")),
                         {2: ["reboot"], 3: ["reboot"]})

    def test_commands_inside_c_strings_count(self):
        f = flags(script('nemesis root 1000 -c "kill 123"', "su -c 'reboot'", 'sh -c "rm -rf /system/x"'))
        self.assertEqual(f[2], ["as-uid", "kill"])
        self.assertEqual(f[3], ["reboot", "as-uid"])
        self.assertEqual(f[4], ["system-path"])

    def test_function_bodies_and_continuations(self):
        f = flags(script("fail() { echo no; /system/xbin/nemesis remount ro >/dev/null 2>&1; exit 1; }",
                         "cp a \\", "  /system/app/b"))
        self.assertEqual(f, {2: ["remount"], 3: ["system-path"]})

    def test_heredoc_body_is_skipped(self):
        f = flags(script("cat > /sdcard/x <<EOF", "reboot", "EOF", "true"))
        self.assertEqual(f, {})

    def test_info_flags(self):
        f = flags(script("setprop ctl.start foo", "curl -o /sdcard/x https://example.com",
                         "settings put global x 1", "insmod /sdcard/x.ko", "setprop sys.powerctl reboot"))
        self.assertEqual(f, {2: ["setprop"], 3: ["network"], 4: ["settings"], 5: ["kmod"], 6: ["reboot"]})
        self.assertFalse(validate.RULES["setprop"][0])
        self.assertTrue(validate.RULES["kmod"][0])

    def test_ev6_fixes_scripts(self):
        # the real ev6.fixes services: root, but no system writes
        got = {}
        for name in ("eth0-guard.sh", "aa-recover.sh", "status.sh"):
            for f in validate.scan_script((FIXTURES / "scripts" / name).read_text(), name, {"dev.ev6fixes.status"}):
                got[(name, f["line"])] = f["rules"]
        self.assertEqual(got, {("eth0-guard.sh", 28): ["setprop"], ("aa-recover.sh", 29): ["as-uid", "kill"]})

    def test_launcher_install_script(self):
        f = flags((FIXTURES / "scripts" / "install-launcher.sh").read_text())
        self.assertEqual(sorted(f), [16, 33, 34, 35, 36, 37, 40, 43, 47])
        self.assertEqual(f[33], ["remount"])
        self.assertEqual(f[34], ["system-path"])

    def test_launcher_restore_script(self):
        f = flags((FIXTURES / "scripts" / "restore-launcher.sh").read_text())
        self.assertEqual(f[29], ["system-path"])  # dalvik-cache
        self.assertEqual(f[35], ["reboot"])


@mock.patch.object(validate, "find_aapt", lambda: None)
class Packages(unittest.TestCase):
    def test_review_record(self):
        r = validate.inspect_zip(package(scripts={
            "svc/a.sh": script("sleep 1"), "svc/b.sh": script("mount -o remount,rw /system")}))
        self.assertEqual(r["nemesis"], {"id": "test.pkg", "version": "1.0"})
        rv = r["review"]
        self.assertEqual(rv["types"], ["application", "service"])
        self.assertEqual(rv["apps"], [{"package": "dev.test", "version_code": 3}])
        self.assertEqual(rv["services"], [{"name": "a", "uid": "root", "mode": "restart"},
                                          {"name": "b", "uid": "root", "mode": "restart"}])
        self.assertEqual(rv["root_services"], ["a", "b"])
        self.assertTrue(rv["system_writes"])
        self.assertFalse(rv["execute"])
        self.assertEqual([(f["file"], f["line"]) for f in r["flags"]], [("svc/b.sh", 2)])

    def test_uid_and_missing_uid(self):
        z = make_zip({"NEMESIS.data": nemesis_data(types="service", services=[
            ("a", "a.sh", None), ("b", "b.sh", "1000"), ("c", "c.sh", "0")]),
            "a.sh": "", "b.sh": "", "c.sh": ""})
        self.assertEqual(validate.inspect_zip(z)["review"]["root_services"], ["a", "c"])

    def test_hooks_and_sh_entries_run_as_root(self):
        nd = nemesis_data(types="application").replace("types=application\n", "types=application\npreinstall=s/pre.sh\npreuninstall=s/un.sh\n")
        nd += "\n[app.0]\nkind=sh\npath=bin/st.sh\n\n[app.1]\nkind=sh\npath=bin/me.sh\nuid=1000\n"
        z = make_zip({"NEMESIS.data": nd, "s/pre.sh": script("mount -o remount,rw /system"), "s/un.sh": "",
                      "bin/st.sh": "", "bin/me.sh": ""})
        r = validate.inspect_zip(z)
        rv = r["review"]
        self.assertEqual(rv["hooks"], [{"hook": "preinstall", "path": "s/pre.sh"},
                                       {"hook": "preuninstall", "path": "s/un.sh"}])
        self.assertEqual(rv["sh_entries"], [{"path": "bin/st.sh", "uid": "root"}, {"path": "bin/me.sh", "uid": "1000"}])
        self.assertEqual(rv["root"], ["preinstall hook s/pre.sh", "preuninstall hook s/un.sh", "script bin/st.sh"])
        self.assertEqual([f["file"] for f in r["flags"]], ["s/pre.sh"])
        self.assertEqual(r["warnings"], [])
        z = make_zip({"NEMESIS.data": nemesis_data(types="application").replace(
            "types=application\n", "types=application\npostinstall=missing.sh\n")})
        with self.assertRaisesRegex(validate.Fail, "postinstall"):
            validate.inspect_zip(z)

    def test_tweaks_run_as_root(self):
        z = make_zip({"NEMESIS.data": nemesis_data(types="application"),
                      "tweaks/x/tweak.conf": "name=X\nkind=oneshot\nrisk=system\n",
                      "tweaks/x/enable.sh": script("setprop a b"),
                      "tweaks/y/tweak.conf": "name=Y\nkind=service\nretired=1\n", "tweaks/y/run.sh": ""})
        rv = validate.inspect_zip(z)["review"]
        self.assertEqual(rv["tweaks"], [
            {"id": "x", "name": "X", "kind": "oneshot", "risk": "system", "retired": False},
            {"id": "y", "name": "Y", "kind": "service", "risk": "normal", "retired": True}])
        self.assertEqual(rv["root"], ["tweak x (through Tweaks)", "tweak y (through Tweaks)"])
        text = "\n".join(validate.describe({"review": rv}))
        self.assertIn("adds the tweak `x` (oneshot, changes the system)", text)
        self.assertIn("runs as root: `tweak x (through Tweaks)`", text)

    def test_execute(self):
        for extra in ("\ntype=execute\n", ""):
            nd = nemesis_data(types="application") + extra
            z = make_zip({"NEMESIS.data": nd})
            self.assertEqual(validate.inspect_zip(z)["review"]["execute"], bool(extra))
        z = make_zip({"NEMESIS.data": nemesis_data(types="execute")})
        self.assertTrue(validate.inspect_zip(z)["review"]["execute"])

    def test_malformed(self):
        cases = {
            b"not a zip": "not a zip",
            make_zip({"pkg/NEMESIS.data": "x"}): "zip the package's contents",
            make_zip({"NEMESIS.data": "[app.0]\npath=x\n"}): "no [nemesis]",
            make_zip({"NEMESIS.data": nemesis_data(apps=[("app/x.apk", "a.b")])}): "isn't in the zip",
            make_zip({"NEMESIS.data": nemesis_data(), "../evil": "x"}): "unsafe path",
            make_zip({"NEMESIS.data": nemesis_data(apps=[("x.apk", "a.b")]), "x.apk": apk("c.d", 1)}):
                "package=a.b but x.apk is c.d",
        }
        for data, msg in cases.items():
            with self.assertRaises(validate.Fail) as c:
                validate.inspect_zip(data)
            self.assertIn(msg, str(c.exception))

    def test_binary_is_noted(self):
        z = make_zip({"NEMESIS.data": nemesis_data(types="service"), "bin/tool": b"\x7fELF\x01\x01"})
        r = validate.inspect_zip(z)
        self.assertEqual(r["flags"], [{"file": "bin/tool", "line": 0, "text": "", "rules": ["binary"]}])
        self.assertFalse(r["review"]["system_writes"])


class Axml(unittest.TestCase):
    def test_utf16_and_utf8(self):
        for utf8 in (False, True):
            self.assertEqual(validate.parse_axml_manifest(axml("dev.x", 42, utf8)),
                             {"package": "dev.x", "version_code": 42})

    def test_blank_attribute_names_use_resource_ids(self):
        self.assertEqual(validate.parse_axml_manifest(axml("dev.x", 7, blank_names=True))["version_code"], 7)

    def test_real_manifest(self):
        # kia-menu's Edit Menu, built with aapt
        m = validate.parse_axml_manifest((FIXTURES / "kia-menu-editor.AndroidManifest.xml").read_bytes())
        self.assertEqual(m, {"package": "dev.kiamenu.editor", "version_code": 6})

    def test_aapt_agrees(self):
        aapt = validate.find_aapt()
        if not aapt:
            self.skipTest("no aapt (set ANDROID_HOME)")
        a = apk("dev.x", 42)
        self.assertEqual(validate.apk_info_aapt(aapt, a), {"package": "dev.x", "version_code": 42})


if __name__ == "__main__":
    unittest.main()
