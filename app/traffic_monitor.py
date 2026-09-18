"""Per-interface traffic history and bandwidth summaries."""

import html
import math
from datetime import datetime, timedelta, timezone

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app import main as core, migrations, router_exec


COMMAND="/interface print stats-detail as-value without-paging"


def _now(): return datetime.now(timezone.utc)


def _parse(text):
    rows=[]
    for line in (text or "").splitlines():
        line=line.strip()
        if not line or "=" not in line: continue
        row={}
        for part in line.split(";"):
            if "=" in part:
                k,v=part.split("=",1); row[k.strip()]=v.strip().strip('"')
        if row and row.get("name"): rows.append(row)
    return rows


def _int(v):
    try:return int(str(v or "0"))
    except Exception:return None


def collect(router_id:int):
    migrations.migrate()
    with core.db() as conn:
        r=conn.execute("SELECT id,site_name,vpn_ip,enabled,lifecycle_state FROM routers WHERE id=?",(router_id,)).fetchone()
    if not r or not r["enabled"] or (r["lifecycle_state"] or "production")=="retired": return []
    rows=_parse(router_exec.read(r["vpn_ip"],COMMAND,timeout=35,label="Traffic counters"))
    captured=_now()
    with core.db() as conn:
        for x in rows:
            name=x.get("name",""); rx=_int(x.get("rx-byte") or x.get("rx-bytes")); tx=_int(x.get("tx-byte") or x.get("tx-bytes"))
            prev=conn.execute(
                "SELECT captured_at,rx_bytes,tx_bytes FROM router_traffic_history WHERE router_id=? AND interface=? ORDER BY id DESC LIMIT 1",
                (router_id,name),
            ).fetchone()
            interval=rx_bps=tx_bps=None; drx=dtx=None
            if prev:
                try: interval=(captured-datetime.fromisoformat(prev["captured_at"])).total_seconds()
                except Exception: interval=None
                if interval and interval>0 and rx is not None and tx is not None and prev["rx_bytes"] is not None and prev["tx_bytes"] is not None:
                    drx=rx-int(prev["rx_bytes"]); dtx=tx-int(prev["tx_bytes"])
                    if drx>=0 and dtx>=0:
                        rx_bps=drx*8/interval; tx_bps=dtx*8/interval
                    else:
                        drx=dtx=None
            conn.execute(
                """INSERT INTO router_traffic_history(router_id,captured_at,interface,rx_bytes,tx_bytes,interval_seconds,rx_bps,tx_bps,rx_delta_bytes,tx_delta_bytes)
                   VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (router_id,captured.isoformat(),name,rx,tx,interval,rx_bps,tx_bps,drx,dtx),
            )
        cutoff=(captured-timedelta(days=90)).isoformat()
        conn.execute("DELETE FROM router_traffic_history WHERE router_id=? AND captured_at<?",(router_id,cutoff))
    return rows


def _pct(values,p):
    vals=sorted(v for v in values if v is not None)
    if not vals:return 0.0
    idx=max(0,min(len(vals)-1,math.ceil(len(vals)*p)-1))
    return float(vals[idx])


def register(app,page_func):
    @app.get("/traffic/{router_id}",response_class=HTMLResponse)
    def page(router_id:int,request:Request):
        user=core.require_web_admin(request)
        if not user:return RedirectResponse("/login",303)
        try: collect(router_id)
        except Exception: pass
        hours=int(request.query_params.get("hours","24") or 24)
        hours=24 if hours not in {24,168,720} else hours
        cutoff=(_now()-timedelta(hours=hours)).isoformat()
        with core.db() as conn:
            r=conn.execute("SELECT id,site_name,model,vpn_ip FROM routers WHERE id=?",(router_id,)).fetchone()
            rows=conn.execute(
                """SELECT * FROM router_traffic_history WHERE router_id=? AND captured_at>=?
                   ORDER BY interface,captured_at""",(router_id,cutoff)
            ).fetchall()
        if not r:return RedirectResponse("/operations",303)
        by={}
        for x in rows: by.setdefault(x["interface"],[]).append(x)
        rendered=[]
        for name,samples in sorted(by.items()):
            rx=[x["rx_bps"] for x in samples if x["rx_bps"] is not None]; tx=[x["tx_bps"] for x in samples if x["tx_bps"] is not None]
            rx_bytes=sum(max(0,x["rx_delta_bytes"] or 0) for x in samples); tx_bytes=sum(max(0,x["tx_delta_bytes"] or 0) for x in samples)
            rendered.append(
                f'<tr><td><strong>{html.escape(name)}</strong></td><td>{(sum(rx)/len(rx)/1e6) if rx else 0:.2f}</td><td>{(sum(tx)/len(tx)/1e6) if tx else 0:.2f}</td>'
                f'<td>{(max(rx)/1e6) if rx else 0:.2f} / {(max(tx)/1e6) if tx else 0:.2f}</td><td>{_pct(rx,0.95)/1e6:.2f} / {_pct(tx,0.95)/1e6:.2f}</td>'
                f'<td>{rx_bytes/1e9:.3f} / {tx_bytes/1e9:.3f}</td><td>{len(samples)}</td></tr>'
            )
        body=f'''<div class="panel pad"><h2>Traffic history · {html.escape(r["site_name"])}</h2>
<div class="inline"><a href="/traffic/{router_id}?hours=24"><button>24h</button></a><a href="/traffic/{router_id}?hours=168"><button>7d</button></a><a href="/traffic/{router_id}?hours=720"><button>30d</button></a></div>
<div class="muted" style="margin-top:8px">Rates are calculated from RouterOS byte-counter deltas; counter resets are discarded.</div></div>
<div class="panel"><table><thead><tr><th>Interface</th><th>Avg RX Mbps</th><th>Avg TX Mbps</th><th>Peak RX/TX Mbps</th><th>95th RX/TX Mbps</th><th>Usage RX/TX GB</th><th>Samples</th></tr></thead><tbody>{''.join(rendered) or '<tr><td colspan="7">No traffic history yet.</td></tr>'}</tbody></table></div>'''
        return page_func("Traffic History",body,user,"operations")
