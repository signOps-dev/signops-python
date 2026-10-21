"""Runs against the real API with a test key: SIGNOPS_KEY=sk_test_... python3 -m unittest discover -s tests"""
import hashlib
import hmac
import json
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from signops import SignOps, SignOpsError  # noqa: E402

KEY = os.environ.get("SIGNOPS_KEY")


@unittest.skipUnless(KEY, "set SIGNOPS_KEY to a test key")
class Api(unittest.TestCase):
    s = SignOps(KEY, base_url=os.environ.get("SIGNOPS_BASE", "https://api.signops.dev")) if KEY else None

    def test_devices_topics_push(self):
        d = self.s.devices.add(user_id="usr_py", token=f"py-test-token-{time.time()}", platform="android", name="Python test")
        self.assertTrue(d.id.startswith("dev_"))
        self.assertGreaterEqual(len(self.s.devices.list("usr_py")), 1)
        self.s.topics.subscribe("py-test", user_id="usr_py")
        p = self.s.push.send(topic="py-test", title="From signops for Python", body="Test", data={"order": 1})
        self.assertTrue(p.id.startswith("msg_"))
        later = self.s.push.send(user_id="usr_py", title="Later", body="x", send_at=time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(time.time() + 3600)))
        self.assertEqual(later.status, "scheduled")
        self.assertEqual(self.s.push.cancel(later.id).status, "cancelled")
        self.assertTrue(self.s.devices.remove(d.id).removed)

    def test_templates(self):
        t = self.s.templates.save("py_paid", title="Rs {{amount}} received", body="Thanks {{name|there}}")
        self.assertEqual([f.name for f in t.fields], ["amount", "name"])
        self.s.devices.add(user_id="usr_py_t", token=f"py-tpl-{time.time()}", platform="android")
        self.assertEqual(self.s.push.send(user_id="usr_py_t", template="py_paid", fields={"amount": 499}).template, "py_paid")
        with self.assertRaises(SignOpsError) as e:
            self.s.push.send(user_id="usr_py_t", template="py_paid")
        self.assertIn("amount", e.exception.message)
        self.s.templates.remove("py_paid")

    def test_errors(self):
        with self.assertRaises(SignOpsError) as e:
            self.s.push.send(title="no target")
        self.assertEqual((e.exception.status, e.exception.code), (400, "invalid_request"))
        with self.assertRaises(SignOpsError) as e:
            self.s.approve.create(user_id="usr_nobody", context="x")
        self.assertEqual(e.exception.code, "not_found")
        with self.assertRaises(SignOpsError) as e:
            self.s.otp.send(email="a@example.in")
        self.assertEqual(e.exception.code, "not_allowed")
        self.assertTrue(self.s.approve.enroll_token("usr_py").token.startswith("enr_"))


class Webhooks(unittest.TestCase):
    def test_verify(self):
        s = SignOps("sk_test_x", webhook_secret="whsec_test")
        body = json.dumps({"id": "evt_1", "type": "push.sent", "data": {}})
        t = int(time.time())
        header = f"t={t},v1={hmac.new(b'whsec_test', f'{t}.{body}'.encode(), hashlib.sha256).hexdigest()}"
        self.assertEqual(s.webhooks.verify(body, header).type, "push.sent")
        self.assertEqual(s.webhooks.verify(body.encode(), header)["id"], "evt_1")
        with self.assertRaises(SignOpsError):
            s.webhooks.verify(body + " ", header)
        with self.assertRaises(SignOpsError):
            s.webhooks.verify(body, f"t={t - 600},v1=00")

    def test_publishable_key_refused(self):
        with self.assertRaises(ValueError):
            SignOps("pk_test_x")


if __name__ == "__main__":
    unittest.main()
