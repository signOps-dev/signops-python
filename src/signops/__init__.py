"""SignOps for Python: push notifications to Android, iOS and the web, push approval of logins, passkeys and webhooks.

    from signops import SignOps
    signops = SignOps(os.environ["SIGNOPS_KEY"])
    signops.push.send(user_id="usr_8f21c4", title="Your order is out for delivery", body="Ravi is 10 minutes away.")

Docs: https://signops.dev/docs/. Standard library only, Python 3.9 and later.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import random
import time
import uuid
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Union

__version__ = "0.1.0"
__all__ = ["SignOps", "SignOpsError", "Obj"]


class SignOpsError(Exception):
    """An error from the API, with its HTTP status and the documented code (invalid_request, not_allowed, ...)."""

    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


class Obj(dict):
    """A result you can read as result["valid"] or result.valid."""

    def __getattr__(self, name: str) -> Any:
        try:
            return self[name]
        except KeyError as e:
            raise AttributeError(name) from e


def _wrap(v: Any) -> Any:
    if isinstance(v, dict):
        return Obj({k: _wrap(x) for k, x in v.items()})
    if isinstance(v, list):
        return [_wrap(x) for x in v]
    return v


def _q(s: str) -> str:
    return urllib.parse.quote(s, safe="")


class SignOps:
    def __init__(self, key: Optional[str] = None, base_url: str = "https://api.signops.dev", webhook_secret: Optional[str] = None,
                 timeout: float = 30, max_retries: int = 2):
        key = key or os.environ.get("SIGNOPS_KEY")
        if not key:
            raise ValueError("SignOps: pass your secret key, or set SIGNOPS_KEY.")
        if key.startswith("pk_"):
            raise ValueError("SignOps: this is a publishable key. On your server use the secret key, sk_live_... or sk_test_....")
        self._key = key
        self._base = base_url.rstrip("/")
        self._timeout = timeout
        self._retries = max_retries
        self._hook_secret = webhook_secret or os.environ.get("SIGNOPS_WEBHOOK_SECRET")
        self.push = _Push(self)
        self.devices = _Devices(self)
        self.topics = _Topics(self)
        self.templates = _Templates(self)
        self.approve = _Approve(self)
        self.passkeys = _Passkeys(self)
        self.otp = _Otp(self)
        self.webhooks = _Webhooks(self)

    def request(self, method: str, path: str, body: Optional[Dict[str, Any]] = None, idempotency_key: Optional[str] = None, timeout: Optional[float] = None) -> Any:
        """Any API call. Every POST carries an Idempotency-Key, so retries on 429, 5xx and network errors never send twice."""
        headers = {"Authorization": f"Bearer {self._key}", "User-Agent": f"signops-python/{__version__}", "Accept": "application/json"}
        data = None
        if body is not None:
            data = json.dumps({k: v for k, v in body.items() if v is not None}).encode()
            headers["Content-Type"] = "application/json"
        if method == "POST":
            headers["Idempotency-Key"] = idempotency_key or str(uuid.uuid4())
        for attempt in range(self._retries + 1):
            req = urllib.request.Request(self._base + path, data=data, method=method, headers=headers)
            try:
                with urllib.request.urlopen(req, timeout=timeout or self._timeout) as r:
                    return _wrap(json.loads(r.read() or b"{}"))
            except urllib.error.HTTPError as e:
                try:
                    j = json.loads(e.read() or b"{}")
                except ValueError:
                    j = {}
                if (e.code == 429 or e.code >= 500) and attempt < self._retries:
                    wait = float(e.headers.get("Retry-After") or 0) or 0.5 * 2 ** attempt
                    time.sleep(min(wait, 10) + random.random() * 0.1)
                    continue
                err = j.get("error") or {}
                raise SignOpsError(e.code, err.get("code", "error"), err.get("message", f"SignOps answered {e.code}")) from None
            except (urllib.error.URLError, TimeoutError, OSError) as e:
                if attempt < self._retries:
                    time.sleep(0.5 * 2 ** attempt)
                    continue
                raise SignOpsError(0, "network_error", f"Could not reach SignOps: {e}") from None
        raise SignOpsError(0, "network_error", "Could not reach SignOps")


class _Push:
    def __init__(self, s: SignOps):
        self._s = s

    def send(self, user_id: Optional[str] = None, user_ids: Optional[List[str]] = None, topic: Optional[str] = None, all: Optional[bool] = None,
             title: Optional[str] = None, body: Optional[str] = None, image: Optional[str] = None, link: Optional[str] = None,
             data: Optional[Dict[str, Any]] = None, send_at: Optional[str] = None, collapse_key: Optional[str] = None,
             template: Optional[str] = None, fields: Optional[Dict[str, Any]] = None, fields_by_user: Optional[Dict[str, Dict[str, Any]]] = None,
             idempotency_key: Optional[str] = None) -> Obj:
        """To one of user_id, user_ids (up to 1,000), topic or all=True. send_at is an ISO time with a zone, up to 30 days ahead.
        template is a template's name, filled with fields; fields_by_user gives each of user_ids its own fields."""
        return self._s.request("POST", "/v1/push", dict(user_id=user_id, user_ids=user_ids, topic=topic, all=all, title=title, body=body, image=image,
                                                        link=link, data=data, send_at=send_at, collapse_key=collapse_key, template=template,
                                                        fields=fields, fields_by_user=fields_by_user), idempotency_key)

    def get(self, id: str) -> Obj:
        return self._s.request("GET", f"/v1/push/{_q(id)}")

    def cancel(self, id: str) -> Obj:
        """Only a scheduled push can be cancelled."""
        return self._s.request("DELETE", f"/v1/push/{_q(id)}")


class _Devices:
    def __init__(self, s: SignOps):
        self._s = s

    def add(self, user_id: str, token: Union[str, Dict[str, Any]], platform: str, name: Optional[str] = None) -> Obj:
        """token is the FCM or APNs token, or for web the PushSubscription your page got. platform is android, ios or web."""
        return self._s.request("POST", "/v1/devices", dict(user_id=user_id, token=token, platform=platform, name=name))

    def remove(self, id: str) -> Obj:
        return self._s.request("DELETE", f"/v1/devices/{_q(id)}")

    def list(self, user_id: str) -> List[Obj]:
        return self._s.request("GET", f"/v1/devices?user_id={_q(user_id)}")["data"]


class _Topics:
    def __init__(self, s: SignOps):
        self._s = s

    def subscribe(self, topic: str, user_id: str) -> Obj:
        return self._s.request("POST", f"/v1/topics/{_q(topic)}/subscribe", dict(user_id=user_id))

    def unsubscribe(self, topic: str, user_id: str) -> Obj:
        return self._s.request("POST", f"/v1/topics/{_q(topic)}/unsubscribe", dict(user_id=user_id))


class _Templates:
    def __init__(self, s: SignOps):
        self._s = s

    def list(self) -> List[Obj]:
        return self._s.request("GET", "/v1/templates")["data"]

    def get(self, name: str) -> Obj:
        return self._s.request("GET", f"/v1/templates/{_q(name)}")

    def save(self, name: str, title: Optional[str] = None, body: Optional[str] = None, description: Optional[str] = None,
             image: Optional[str] = None, link: Optional[str] = None, data: Optional[Dict[str, str]] = None) -> Obj:
        """Creates or replaces a template by name. Write {{field}} or {{field|default}} where values go."""
        return self._s.request("POST", "/v1/templates", dict(name=name, title=title, body=body, description=description, image=image, link=link, data=data))

    def remove(self, name: str) -> Obj:
        return self._s.request("DELETE", f"/v1/templates/{_q(name)}")


class _Approve:
    def __init__(self, s: SignOps):
        self._s = s

    def enroll_token(self, user_id: str) -> Obj:
        """A one-time token your app passes to the SDK to trust this phone for the signed-in user. Good for 10 minutes."""
        return self._s.request("POST", "/v1/approve/enroll-token", dict(user_id=user_id))

    def create(self, user_id: str, context: str, city: Optional[str] = None, browser: Optional[str] = None, ip: Optional[str] = None) -> Obj:
        """Pushes to the user's trusted phones. Show result.match on your login page."""
        return self._s.request("POST", "/v1/approve", dict(user_id=user_id, context=context, city=city, browser=browser, ip=ip))

    def get(self, id: str) -> Obj:
        return self._s.request("GET", f"/v1/approve/{_q(id)}")

    def wait(self, id: str, timeout: int = 120) -> Obj:
        """Blocks until the user answers or the request expires, up to timeout seconds (at most 120)."""
        until = time.time() + min(timeout, 120)
        while True:
            left = max(0, int(until - time.time()))
            a = self._s.request("GET", f"/v1/approve/{_q(id)}?wait={min(left, 25)}", timeout=40)
            if a["status"] != "pending" or time.time() >= until:
                return a

    def create_and_wait(self, user_id: str, context: str, timeout: int = 120, **kw: Any) -> Obj:
        a = self.create(user_id, context, **kw)
        r = self.wait(a["id"], timeout)
        r["match"] = a.get("match")
        return r

    def cancel(self, id: str) -> Obj:
        return self._s.request("POST", f"/v1/approve/{_q(id)}/cancel", {})

    def untrust(self, device_id: str) -> Obj:
        return self._s.request("POST", f"/v1/approve/devices/{_q(device_id)}/remove", {})


class _Passkeys:
    def __init__(self, s: SignOps):
        self._s = s

    def registration_token(self, user_id: str, user_name: Optional[str] = None, display_name: Optional[str] = None, rp_id: Optional[str] = None) -> Obj:
        return self._s.request("POST", "/v1/passkeys/registration-token", dict(user_id=user_id, user_name=user_name, display_name=display_name, rp_id=rp_id))

    def verify(self, signops_token: str) -> Obj:
        """Confirms the signops_token from the browser's passkeys.signIn. Single use. result.valid and result.user_id."""
        return self._s.request("POST", "/v1/passkeys/verify", dict(signops_token=signops_token))

    def list(self, user_id: str) -> List[Obj]:
        return self._s.request("GET", f"/v1/passkeys?user_id={_q(user_id)}")["data"]

    def remove(self, id: str) -> Obj:
        return self._s.request("DELETE", f"/v1/passkeys/{_q(id)}")


class _Otp:
    def __init__(self, s: SignOps):
        self._s = s

    def send(self, email: str, app_name: Optional[str] = None) -> Obj:
        return self._s.request("POST", "/v1/otp/send", dict(email=email, app_name=app_name))

    def verify(self, otp_id: str, code: str) -> Obj:
        return self._s.request("POST", "/v1/otp/verify", dict(otp_id=otp_id, code=code))


class _Webhooks:
    def __init__(self, s: SignOps):
        self._s = s

    def verify(self, payload: Union[bytes, str], header: Optional[str], secret: Optional[str] = None, tolerance: int = 300) -> Obj:
        """Checks the SignOps-Signature header against the raw body and returns the event. Raises SignOpsError if it does not match."""
        key = secret or self._s._hook_secret
        if not key:
            raise ValueError("SignOps: no webhook secret. Pass it, or set SIGNOPS_WEBHOOK_SECRET.")
        parts = dict(p.strip().split("=", 1) for p in (header or "").split(",") if "=" in p)
        try:
            t = int(parts.get("t", ""))
        except ValueError:
            raise SignOpsError(400, "invalid_signature", "No SignOps-Signature header, or it is not t=...,v1=...") from None
        if abs(time.time() - t) > tolerance:
            raise SignOpsError(400, "invalid_signature", "The event is older than 5 minutes.")
        body = payload.decode() if isinstance(payload, bytes) else payload
        want = hmac.new(key.encode(), f"{t}.{body}".encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(want, parts.get("v1", "")):
            raise SignOpsError(400, "invalid_signature", "The signature does not match. Check the secret and that the body is the raw one.")
        return _wrap(json.loads(body))
