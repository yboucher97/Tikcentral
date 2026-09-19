"""Read-only interface health/history collection."""

import html
from datetime import datetime, timezone

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app import main as core, migrations, router_exec


STATS_COMMAND = "/interface print stats-detail as-value without-paging"
ETHERNET_COMMAND = "/interface ethernet print detail as-value without-paging"
ETHERNET_MONITOR_COMMAND = "/interface ethernet monitor [find] once as-value"


def _now():
    return datetime.now(timezone.utc).isoformat()


def _router(router_id):
    with core.db() as conn:
        return conn.execute(
            "SELECT id,site_name,identity,model,vpn_ip,enabled,lifecycle_state FROM routers WHERE id=?",
            (router_id,),
        ).fetchone()


def _bool(value):
    s=str(value or "").strip().lower()
    if s in {"true","yes","1"}: return 1
    if s in {"false","no","0"}: return 0
    return None


def _int(value):
    try: return int(str(value or "0").strip())
    except Exception: return None


def _parse_as_value(text: str):
    rows=[]
    for raw in (text or "").splitlines():
        line=raw.strip()
        if not line or "=" not in line:
            continue
        row={}
        for part in line.split(";"):
            if "=" not in part:
                continue
            key,val=part.split("=",1)
            row[key.strip()]=val.strip().strip('"')
        if row:
            rows.append(row)
    return rows


def collect(router_id:int):
    migrations.migrate()
    router=_router(router_id)
    if not router or not router["enabled"] or (router["lifecycle_state"] or "production") == "retired":
        return None

    stats=_parse_as_value(router_exec.read(router["vpn_ip"],STATS_COMMAND,timeout=35,label="Interface statistics"))
    try:
        ethernet=_parse_as_value(router_exec.read(router["vpn_ip"],ETHERNET_COMMAND,timeout=35,label="Ethernet detail"))
    except Exception:
        ethernet=[]
    try:
        monitor=_parse_as_value(router_exec.read(router["vpn_ip"],ETHERNET_MONITOR_COMMAND,timeout=35,label="Ethernet monitor"))
    except Exception:
        monitor=[]
    eth_by_name={x.get("name",""):x for x in ethernet if x.get("name")}
    monitor_by_name={x.get("name",""):x for x in monitor if x.get("name")}
    captured=_now()
    rows=[]
    for x in stats:
        name=x.get("name") or ""
        if not name:
            continue
        e=eth_by_name.get(name,{})
        mon=monitor_by_name.get(name,{})
        row={
            "name":name,
            "interface_type":x.get("type") or e.get("type") or "",
            "running":_bool(x.get("running")),
            "disabled":_bool(x.get("disabled")),
            "rx_bytes":_int(x.get("rx-byte") or x.get("rx-bytes")),
            "tx_bytes":_int(x.get("tx-byte") or x.get("tx-bytes")),
            "rx_packets":_int(x.get("rx-packet") or x.get("rx-packets")),
            "tx_packets":_int(x.get("tx-packet") or x.get("tx-packets")),
            "rx_errors":_int(x.get("rx-error") or x.get("rx-errors")),
            "tx_errors":_int(x.get("tx-error") or x.get("tx-errors")),
            "rx_drops":_int(x.get("rx-drop") or x.get("rx-drops")),
            "tx_drops":_int(x.get("tx-drop") or x.get("tx-drops")),
            "link_downs":_int(e.get("link-downs") or x.get("link-downs")),
            "rate":mon.get("rate") or e.get("rate") or x.get("rate") or "",
            "full_duplex":_bool(mon.get("full-duplex") or e.get("full-duplex") or x.get("full-duplex")),
            "auto_negotiation":mon.get("auto-negotiation") or e.get("auto-negotiation") or "",
            "poe_out":mon.get("poe-out") or mon.get("poe-out-status") or e.get("poe-out") or e.get("poe-out-status") or "",
        }
        rows.append(row)

    with core.db() as conn:
        for x in rows:
            conn.execute(
                """INSERT INTO router_interface_history
                   (router_id,captured_at,name,interface_type,running,disabled,rx_bytes,tx_bytes,
                    rx_packets,tx_packets,rx_errors,tx_errors,rx_drops,tx_drops,link_downs,
                    rate,full_duplex,auto_negotiation,poe_out)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (router_id,captured,x["name"],x["interface_type"],x["running"],x["disabled"],
                 x["rx_bytes"],x["tx_bytes"],x["rx_packets"],x["tx_packets"],x["rx_errors"],
                 x["tx_errors"],x["rx_drops"],x["tx_drops"],x["link_downs"],x["rate"],
                 x["full_duplex"],x["auto_negotiation"],x["poe_out"]),
            )
        conn.execute(
            """DELETE FROM router_interface_history WHERE router_id=? AND id NOT IN
               (SELECT id FROM router_interface_history WHERE router_id=? ORDER BY id DESC LIMIT 30000)""",
            (router_id,router_id),
        )
    return rows


def _delta(now, prev, field):
    if now[field] is None or prev is None or prev[field] is None:
        return None
    try:
        return int(now[field]) - int(prev[field])
    except Exception:
        return None


def register(app,page_func):
    migrations.migrate()

    @app.get("/interfaces/{router_id}",response_class=HTMLResponse)
    def interface_page(router_id:int,request:Request):
        user=core.require_web_admin(request)
        if not user: return RedirectResponse("/login",303)
        router=_router(router_id)
        if not router: return RedirectResponse("/operations",303)
        try: collect(router_id)
        except Exception: pass
        with core.db() as conn:
            latest_time=conn.execute(
                "SELECT MAX(captured_at) t FROM router_interface_history WHERE router_id=?",(router_id,)
            ).fetchone()["t"]
            latest=conn.execute(
                "SELECT * FROM router_interface_history WHERE router_id=? AND captured_at=? ORDER BY name",
                (router_id,latest_time or ""),
            ).fetchall() if latest_time else []
            prior={}
            for x in latest:
                prior[x["name"]]=conn.execute(
                    """SELECT * FROM router_interface_history WHERE router_id=? AND name=? AND captured_at<?
                       ORDER BY captured_at DESC,id DESC LIMIT 1""",
                    (router_id,x["name"],x["captured_at"]),
                ).fetchone()
        rows=[]
        for x in latest:
            p=prior.get(x["name"])
            err_delta=sum(v or 0 for v in (_delta(x,p,"rx_errors"),_delta(x,p,"tx_errors"),_delta(x,p,"rx_drops"),_delta(x,p,"tx_drops")))
            link_delta=_delta(x,p,"link_downs")
            state="Disabled" if x["disabled"] else ("Up" if x["running"] else "Down")
            rows.append(
                f'<tr><td><strong>{html.escape(x["name"])}</strong><div class="muted">{html.escape(x["interface_type"] or "")}</div></td>'
                f'<td>{state}</td><td>{html.escape(x["rate"] or "-")}<div class="muted">{"full" if x["full_duplex"]==1 else ("half" if x["full_duplex"]==0 else "-")} duplex</div></td>'
                f'<td>{x["rx_errors"] if x["rx_errors"] is not None else "—"} / {x["tx_errors"] if x["tx_errors"] is not None else "—"}<div class="muted">Δ {err_delta}</div></td>'
                f'<td>{x["rx_drops"] if x["rx_drops"] is not None else "—"} / {x["tx_drops"] if x["tx_drops"] is not None else "—"}</td>'
                f'<td>{x["link_downs"] if x["link_downs"] is not None else "—"}<div class="muted">Δ {link_delta if link_delta is not None else "—"}</div></td>'
                f'<td>{html.escape(x["poe_out"] or "-")}</td></tr>'
            )
        body=f'''<div class="panel pad"><h2>Interface health · {html.escape(router["site_name"])}</h2>
<div class="muted">Link state, counters, errors/drops, link-down count, negotiated rate/duplex and PoE status where RouterOS exposes them.</div>
<div style="margin-top:12px"><a href="/operations/{router_id}"><button>Back to router</button></a><a href="/timeline/{router_id}"><button>Timeline</button></a></div></div>
<div class="panel"><table><thead><tr><th>Interface</th><th>State</th><th>Rate / duplex</th><th>RX/TX errors</th><th>RX/TX drops</th><th>Link downs</th><th>PoE</th></tr></thead><tbody>{''.join(rows) or '<tr><td colspan="7">No interface history available.</td></tr>'}</tbody></table></div>'''
        return page_func("Interface Health",body,user,"operations")
