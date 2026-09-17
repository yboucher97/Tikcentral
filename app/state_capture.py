"""Read-only state capture for reliability and configuration history."""

import hashlib
import json
import re
from datetime import datetime, timezone

from app import main as core, migrations, router_exec


def now_iso():
    return datetime.now(timezone.utc).isoformat()


MANAGEMENT_STATE_COMMAND = r'''
/interface/wireguard print detail where name="opticable-wg";
/interface/wireguard/peers print detail where interface="opticable-wg";
/ip/address print detail where interface="opticable-wg";
/ip/route print detail where comment~"Tikcentral";
/ip/service print detail where name="ssh" or name="winbox" or name="api";
/user print detail where name="tikcentral";
/user/ssh-keys print detail where user="tikcentral";
/ip/firewall/filter print detail where comment~"Tikcentral"
'''.strip()


WAN_STATE_COMMAND = r'''
:put ("TC|active_default_routes|" . [/ip/route print count-only where dst-address=0.0.0.0/0 active=yes]);
:put ("TC|dhcp_bound|" . [/ip/dhcp-client print count-only where status=bound]);
:put ("TC|pppoe_running|" . [/interface/pppoe-client print count-only where running=yes]);
:put ("TC|internet_ping|" . [/ping address=1.1.1.1 count=2 interval=300ms]);
:do { :resolve "cloudflare.com"; :put "TC|dns_ok|1" } on-error={ :put "TC|dns_ok|0" };
:put "TC|WAN_DETAIL_BEGIN";
/ip/dhcp-client print detail without-paging;
/interface/pppoe-client print detail without-paging;
/ip/route print detail without-paging where dst-address=0.0.0.0/0;
/ip/address print detail without-paging where dynamic=yes
'''.strip()


def _router(router_id: int):
    with core.db() as conn:
        return conn.execute(
            "SELECT id,site_name,vpn_ip,enabled FROM routers WHERE id=?",
            (router_id,),
        ).fetchone()


def capture_config_snapshot(router_id: int, *, source_kind: str = "", source_id: int | None = None, actor: str = ""):
    migrations.migrate()
    router = _router(router_id)
    if not router or not router["enabled"]:
        return None
    content = router_exec.read(router["vpn_ip"], "/export terse", timeout=90, label="Configuration snapshot")
    digest = hashlib.sha256(content.encode()).hexdigest()
    captured = now_iso()
    with core.db() as conn:
        cur = conn.execute(
            """INSERT OR IGNORE INTO router_snapshots
               (router_id,captured_at,sha256,content,source_kind,source_id,source_actor)
               VALUES(?,?,?,?,?,?,?)""",
            (router_id, captured, digest, content, source_kind[:60], source_id, actor[:160]),
        )
        if cur.rowcount:
            return int(cur.lastrowid)
        row = conn.execute(
            "SELECT id FROM router_snapshots WHERE router_id=? AND sha256=?",
            (router_id, digest),
        ).fetchone()
        return int(row["id"]) if row else None


def capture_management_known_good(
    router_id: int,
    *,
    source_kind: str = "",
    source_id: int | None = None,
    actor: str = "",
):
    migrations.migrate()
    router = _router(router_id)
    if not router or not router["enabled"]:
        return None
    output = router_exec.read(
        router["vpn_ip"],
        MANAGEMENT_STATE_COMMAND,
        timeout=45,
        label="Known-good management capture",
    )
    content = router_exec.sanitize(output, 50000)
    digest = hashlib.sha256(content.encode()).hexdigest()
    captured = now_iso()
    with core.db() as conn:
        conn.execute(
            """INSERT INTO router_management_known_good
               (router_id,captured_at,sha256,content,source_kind,source_id,source_actor)
               VALUES(?,?,?,?,?,?,?)
               ON CONFLICT(router_id) DO UPDATE SET
                 captured_at=excluded.captured_at,sha256=excluded.sha256,content=excluded.content,
                 source_kind=excluded.source_kind,source_id=excluded.source_id,
                 source_actor=excluded.source_actor""",
            (router_id, captured, digest, content, source_kind[:60], source_id, actor[:160]),
        )
    return {"captured_at": captured, "sha256": digest, "content": content}


def compare_management_known_good(router_id: int):
    migrations.migrate()
    router = _router(router_id)
    if not router or not router["enabled"]:
        return None
    with core.db() as conn:
        known = conn.execute(
            "SELECT * FROM router_management_known_good WHERE router_id=?",
            (router_id,),
        ).fetchone()
    if not known:
        return {"status": "missing", "known": None, "current": "", "current_sha256": ""}
    output = router_exec.read(
        router["vpn_ip"],
        MANAGEMENT_STATE_COMMAND,
        timeout=45,
        label="Management known-good comparison",
    )
    current = router_exec.sanitize(output, 50000)
    digest = hashlib.sha256(current.encode()).hexdigest()
    return {
        "status": "match" if digest == known["sha256"] else "drift",
        "known": known,
        "current": current,
        "current_sha256": digest,
    }


def _marker(output: str, name: str):
    match = re.search(rf"(?m)^TC\|{re.escape(name)}\|([^\r\n]+)", output or "")
    return match.group(1).strip() if match else ""


def _int_marker(output: str, name: str, default=None):
    value = _marker(output, name)
    try:
        return int(value)
    except Exception:
        return default


def collect_wan_state(router_id: int):
    migrations.migrate()
    router = _router(router_id)
    if not router or not router["enabled"]:
        return None
    raw = router_exec.read(router["vpn_ip"], WAN_STATE_COMMAND, timeout=35, label="WAN telemetry")
    begin = raw.find("TC|WAN_DETAIL_BEGIN")
    detail = raw[begin + len("TC|WAN_DETAIL_BEGIN"):] if begin >= 0 else raw
    summary = router_exec.sanitize(detail.strip(), 30000)
    state = {
        "captured_at": now_iso(),
        "active_default_routes": _int_marker(raw, "active_default_routes", 0) or 0,
        "dhcp_bound": _int_marker(raw, "dhcp_bound", 0) or 0,
        "pppoe_running": _int_marker(raw, "pppoe_running", 0) or 0,
        "internet_ping": _int_marker(raw, "internet_ping", None),
        "dns_ok": _int_marker(raw, "dns_ok", None),
        "summary": summary,
    }
    fp_data = json.dumps(
        {k: state[k] for k in ("active_default_routes", "dhcp_bound", "pppoe_running", "internet_ping", "dns_ok", "summary")},
        sort_keys=True,
    )
    state["fingerprint"] = hashlib.sha256(fp_data.encode()).hexdigest()
    with core.db() as conn:
        conn.execute(
            """INSERT INTO router_wan_history
               (router_id,captured_at,active_default_routes,dhcp_bound,pppoe_running,
                internet_ping,dns_ok,summary,fingerprint)
               VALUES(?,?,?,?,?,?,?,?,?)""",
            (
                router_id, state["captured_at"], state["active_default_routes"],
                state["dhcp_bound"], state["pppoe_running"], state["internet_ping"],
                state["dns_ok"], state["summary"], state["fingerprint"],
            ),
        )
        conn.execute(
            """DELETE FROM router_wan_history WHERE router_id=? AND id NOT IN
               (SELECT id FROM router_wan_history WHERE router_id=? ORDER BY id DESC LIMIT 8640)""",
            (router_id, router_id),
        )
    return state
