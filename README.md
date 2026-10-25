# signops

SignOps for Python: push notifications to Android, iOS and the web, push approval of logins, passkeys and webhooks, on one API key and your own user ids. Website: https://signops.dev. Docs: https://signops.dev/docs/

Not on PyPI yet. Until it is, install from this repository:

```sh
pip install git+https://github.com/signops-dev/signops-python
```

```python
import os
from signops import SignOps, SignOpsError

signops = SignOps(os.environ["SIGNOPS_KEY"])  # sk_live_... or sk_test_...

signops.devices.add(user_id="usr_8f21c4", token=fcm_token, platform="android")
signops.push.send(user_id="usr_8f21c4", title="Your order is out for delivery", body="Ravi is 10 minutes away.")
signops.push.send(topic="offers", title="Weekend offer", body="20% off fruit", send_at="2026-10-24T18:00:00+05:30")

challenge = signops.approve.create(user_id="usr_8f21c4", context="Sign in from Chrome on Windows")
result = signops.approve.wait(challenge.id, timeout=120)  # show challenge.match on your login page first
if result.status == "approved":
    start_session(result.user_id)

check = signops.passkeys.verify(request.form["signops_token"])
event = signops.webhooks.verify(request.get_data(), request.headers["SignOps-Signature"])  # SIGNOPS_WEBHOOK_SECRET
```

Results read as `result.valid` or `result["valid"]`. Errors raise `SignOpsError` with `status`, `code` and `message`. Every POST carries an `Idempotency-Key`, so retries never send twice. Standard library only; Python 3.9 or later.
