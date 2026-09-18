"""Public WireGuard endpoint enrichment using a cached free IP lookup."""

import ipaddress
import json
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

from app import events, main as core, migrations, settings


def _now():
    return datetime.now(timezone.utc)


def _iso(dt):
    return dt.isoformat()


def _public_v4(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
        return ip.version == 4 and not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved)
    except ValueError:
        return False


def _lookup(ip: str) -> dict:
    url = settings.IP_LOOKUP_URL_TEMPLATE.format(ip=urllib.parse.quote(ip, safe=""))
    req = urllib.request.Request(url, headers={"User-Agent": "Tikcentral/1.0"})
    with urllib.request.urlopen(req, timeout=settings.IP_LOOKUP_TIMEOUT) as response:
        payload = json.loads(response.read().decode("utf-8", "replace"))
    if not payload.get("success", True):
        raise RuntimeError(payload.get("message") or "IP lookup failed")
    connection = payload.get("connection") or {}
    return {
        "isp": str(connection.get("isp") or payload.get("isp") or ""),
        "organization": str(connection.get("org") or payload.get("org") or ""),
        "asn": str(connection.get("asn") or payload.get("asn") or ""),
        "country": str(payload.get("country") or ""),
        "region": str(payload.get("region") or ""),
        "city": str(payload.get("city") or ""),
    }


def current_for_router(router_id: int):
    migrations.migrate()
    with core.db() as conn:
        return conn.execute(
            """SELECT * FROM router_public_ip_history
               WHERE router_id=? ORDER BY last_seen_at DESC,id DESC LIMIT 1""",
            (router_id,),
        ).fetchone()


def refresh_all() -> int:
    """Refresh public-IP sightings and enrich only new/stale IPs."""
    migrations.migrate()
    peers = core.wireguard_peers()
    now = _now()
    cutoff = now - timedelta(days=settings.IP_LOOKUP_REFRESH_DAYS)
    updates = 0
    with core.db() as conn:
        routers = conn.execute(
            "SELECT id,site_name,public_key FROM routers WHERE enabled=1 ORDER BY id"
        ).fetchall()
    for router in routers:
        public_ip = (peers.get(router["public_key"]) or {}).get("public_ip") or ""
        if not _public_v4(public_ip):
            continue
        with core.db() as conn:
            current = conn.execute(
                "SELECT * FROM router_public_ip_history WHERE router_id=? AND public_ip=?",
                (router["id"], public_ip),
            ).fetchone()
            previous = conn.execute(
                "SELECT * FROM router_public_ip_history WHERE router_id=? ORDER BY last_seen_at DESC,id DESC LIMIT 1",
                (router["id"],),
            ).fetchone()
            if current:
                conn.execute(
                    "UPDATE router_public_ip_history SET last_seen_at=? WHERE id=?",
                    (_iso(now), current["id"]),
                )
            else:
                conn.execute(
                    """INSERT INTO router_public_ip_history
                       (router_id,public_ip,first_seen_at,last_seen_at,lookup_status)
                       VALUES(?,?,?,?, 'pending')""",
                    (router["id"], public_ip, _iso(now), _iso(now)),
                )
            changed = bool(previous and previous["public_ip"] != public_ip)
        stale = True
        if current and current["lookup_at"]:
            try:
                stale = datetime.fromisoformat(current["lookup_at"]) < cutoff
            except Exception:
                stale = True
        if current and current["lookup_status"] == "ok" and not stale:
            continue
        try:
            info = _lookup(public_ip)
            with core.db() as conn:
                conn.execute(
                    """UPDATE router_public_ip_history SET lookup_at=?,lookup_status='ok',
                       lookup_error='',isp=?,organization=?,asn=?,country=?,region=?,city=?
                       WHERE router_id=? AND public_ip=?""",
                    (_iso(now), info["isp"], info["organization"], info["asn"], info["country"],
                     info["region"], info["city"], router["id"], public_ip),
                )
            updates += 1
            if changed:
                events.record(
                    router["id"], "wan", "Public IP changed",
                    f'{previous["public_ip"]} → {public_ip}; ISP={info["isp"] or "-"}; ASN={info["asn"] or "-"}',
                    "info",
                )
        except Exception as exc:
            with core.db() as conn:
                conn.execute(
                    """UPDATE router_public_ip_history SET lookup_at=?,lookup_status='error',lookup_error=?
                       WHERE router_id=? AND public_ip=?""",
                    (_iso(now), str(exc)[:500], router["id"], public_ip),
                )
    return updates
