"""Offline request regressions. No host services or routers are contacted."""

import asyncio
import atexit
import json
import os
import sys
import tempfile
import threading
import unittest
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
_tmp = tempfile.TemporaryDirectory(prefix="tikcentral-request-tests-")
atexit.register(_tmp.cleanup)
os.environ["DB_PATH"] = str(Path(_tmp.name) / "test.db")
os.environ.setdefault("ADMIN_API_KEY", "offline-test-key")
os.environ.setdefault("WG_SERVER_PUBLIC_KEY", "A" * 43 + "=")
os.environ.setdefault("WG_ENDPOINT", "test.invalid:51820")

from fastapi import HTTPException
from starlette.requests import Request
from app import main as core, operations
from app.final import app


def request(payload, *, path="/api/ui/preferences", form=False):
    body = payload.encode() if form else json.dumps(payload).encode()
    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}
    req = Request({"type": "http", "method": "POST" if form else "PUT", "path": path, "headers": []}, receive)
    csrf = core.csrf_token(req)
    req.scope["headers"].append((b"x-csrf-token", csrf.encode()))
    return req


class RequestRegressions(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        with core.db() as conn:
            conn.execute("DELETE FROM user_ui_preferences")
            conn.execute("DELETE FROM users")
            conn.execute("INSERT INTO users(id,email,password_hash,role,created_at,updated_at) VALUES(1,'test@example.invalid','unused','admin','2026-01-01','2026-01-01')")
        self.user = {"id": 1, "email": "test@example.invalid", "role": "admin"}
        self.auth = patch.object(core, "session_user", return_value=self.user)
        self.auth.start()
        self.addCleanup(self.auth.stop)

    async def test_preference_input_shape_and_explicit_deletion(self):
        for value in ([], None, "bad", 42, {"key": "ui:theme"}, {"key": 3, "value": "dark"}, {"key": "ui:bad", "value": float("nan")}):
            with self.subTest(value=value), self.assertRaises(HTTPException) as caught:
                await core.update_ui_preference(request(value))
            self.assertEqual(caught.exception.status_code, 400)
        await core.update_ui_preference(request({"key": "ui:theme", "value": "dark"}))
        result = json.loads(core.ui_preferences(request({})).body)
        self.assertEqual(result["preferences"]["ui:theme"], "dark")
        await core.update_ui_preference(request({"key": "ui:theme", "value": None}))
        self.assertEqual(json.loads(core.ui_preferences(request({})).body)["preferences"], {})

    async def test_preferences_remain_account_scoped_and_csrf_protected(self):
        await core.update_ui_preference(request({"key": "table:test", "value": [0, 2]}))
        with patch.object(core, "session_user", return_value={**self.user, "id": 2}):
            self.assertEqual(json.loads(core.ui_preferences(request({})).body)["preferences"], {})
        bad = request({"key": "table:test", "value": []})
        bad.scope["headers"].clear()
        with self.assertRaises(HTTPException) as caught:
            await core.update_ui_preference(bad)
        self.assertEqual(caught.exception.status_code, 403)

    async def assert_loop_available(self, invoke, target, *, during_wait=None):
        loop = asyncio.get_running_loop()
        started, release = asyncio.Event(), threading.Event()
        released = []
        def slow_operation(*args, **kwargs):
            loop.call_soon_threadsafe(started.set)
            released.append(release.wait(2))
        with patch.object(*target, side_effect=slow_operation):
            task = asyncio.create_task(invoke())
            try:
                await asyncio.wait_for(started.wait(), 1)
                # This coroutine, including an unrelated preference read, must
                # run while the router/host operation is still waiting.
                self.assertFalse(task.done())
                self.assertEqual(core.ui_preferences(request({})).status_code, 200)
                if during_wait:
                    during_wait()
            finally:
                release.set()
                await task
        self.assertEqual(released, [True])

    async def test_router_refresh_does_not_freeze_other_requests(self):
        route = next(r for r in app.routes if getattr(r, "path", "") == "/operations/{router_id}/telemetry")
        req = request("csrf=" + core.csrf_token(request({})), path=route.path, form=True)
        await self.assert_loop_available(lambda: route.endpoint(1, req), (operations, "collect_telemetry"))

    async def test_enrollment_does_not_freeze_loop_or_hold_database_writer(self):
        token, public_key = "offline-enrollment-token", "C" * 43 + "="
        now = core.utcnow()
        with core.db() as conn:
            conn.execute("INSERT INTO enrollment_tokens(token_hash,site_name,created_at,expires_at) VALUES(?,?,?,?)", (core.hash_token(token), "Test site", core.iso(now), core.iso(now + timedelta(hours=1))))
        req = request({"token": token, "public_key": public_key}, path="/api/enroll")
        def write_while_waiting():
            with core.db() as conn:
                conn.execute("PRAGMA busy_timeout=100")
                conn.execute("UPDATE users SET updated_at='while-enrolling' WHERE id=1")
        with patch.object(core, "wireguard_peers", return_value={}):
            await self.assert_loop_available(lambda: core.enroll(req), (core, "wg_helper"), during_wait=write_while_waiting)
        with core.db() as conn:
            row = conn.execute("SELECT enabled,lifecycle_state FROM routers WHERE public_key=?", (public_key,)).fetchone()
        self.assertEqual(tuple(row), (1, "new"))


if __name__ == "__main__":
    unittest.main()
