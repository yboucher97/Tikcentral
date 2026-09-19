"""Read-only LTE signal, band and cell history."""

import html
import re
from datetime import datetime, timezone

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app import main as core, migrations, router_exec


LTE_COMMAND = r'''
:put ("TC|LTE_COUNT|" . [/interface/lte print count-only]);
:foreach i in=[/interface/lte find] do={
  :put ("TC|LTE_INTERFACE|" . [/interface/lte get $i name]);
  /interface/lte/monitor $i once;
}
'''.strip()


def _now():
    return datetime.now(timezone.utc).isoformat()


def _router(router_id):
    with core.db() as conn:
        return conn.execute(
            "SELECT id,site_name,identity,model,vpn_ip,enabled,lifecycle_state FROM routers WHERE id=?",
            (router_id,),
        ).fetchone()


def _num(value):
    if value is None: return None
    m=re.search(r"-?\d+(?:\.\d+)?",str(value))
    try: return float(m.group(0)) if m else None
    except Exception: return None


def _parse(raw: str):
    count=re.search(r"(?m)^TC\|LTE_COUNT\|(\d+)",raw or "")
    if not count or int(count.group(1)) == 0:
        return []
    segments=re.split(r"(?m)^TC\|LTE_INTERFACE\|([^\r\n]+)\r?\n?",raw or "")
    rows=[]
    for i in range(1,len(segments),2):
        interface=segments[i].strip()
        text=segments[i+1] if i+1 < len(segments) else ""
        data={}
        for key,val in re.findall(r"(?m)^\s*([a-zA-Z0-9-]+):\s*(.*?)\s*$",text):
            data[key.lower()]=val.strip()
        status=(data.get("status") or "").lower()
        rows.append({
            "interface":interface,
            "registered":1 if status in {"registered","connected"} else (0 if status else None),
            "operator":data.get("current-operator") or data.get("operator") or "",
            "access_technology":data.get("access-technology") or "",
            "band":data.get("band") or "",
            "ca_band":data.get("ca-band") or data.get("ca-bands") or "",
            "cell_id":data.get("cellid") or data.get("cell-id") or "",
            "enb_id":data.get("enb-id") or "",
            "sector_id":data.get("sector-id") or "",
            "phy_cell_id":data.get("phy-cellid") or data.get("phy-cell-id") or "",
            "rsrp":_num(data.get("rsrp")),
            "rsrq":_num(data.get("rsrq")),
            "sinr":_num(data.get("sinr")),
            "rssi":_num(data.get("rssi")),
            "raw":router_exec.sanitize(text,12000),
        })
    return rows


def collect(router_id:int):
    migrations.migrate()
    router=_router(router_id)
    if not router or not router["enabled"] or (router["lifecycle_state"] or "production") == "retired": return None
    raw=router_exec.read(router["vpn_ip"],LTE_COMMAND,timeout=30,label="LTE telemetry")
    rows=_parse(raw)
    if not rows: return []
    captured=_now()
    with core.db() as conn:
        for x in rows:
            conn.execute(
                """INSERT INTO router_lte_history
                   (router_id,captured_at,interface,registered,operator,access_technology,band,ca_band,
                    cell_id,enb_id,sector_id,phy_cell_id,rsrp,rsrq,sinr,rssi,raw)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (router_id,captured,x["interface"],x["registered"],x["operator"],x["access_technology"],
                 x["band"],x["ca_band"],x["cell_id"],x["enb_id"],x["sector_id"],x["phy_cell_id"],
                 x["rsrp"],x["rsrq"],x["sinr"],x["rssi"],x["raw"]),
            )
        conn.execute(
            """DELETE FROM router_lte_history WHERE router_id=? AND id NOT IN
               (SELECT id FROM router_lte_history WHERE router_id=? ORDER BY id DESC LIMIT 12000)""",
            (router_id,router_id),
        )
    return rows


def register(app,page_func):
    migrations.migrate()

    @app.get("/lte/{router_id}",response_class=HTMLResponse)
    def lte_page(router_id:int,request:Request):
        user=core.require_web_admin(request)
        if not user: return RedirectResponse("/login",303)
        router=_router(router_id)
        if not router: return RedirectResponse("/operations",303)
        try: collect(router_id)
        except Exception: pass
        with core.db() as conn:
            rows=conn.execute(
                """SELECT * FROM router_lte_history WHERE router_id=?
                   ORDER BY id DESC LIMIT 300""",(router_id,)
            ).fetchall()
        latest=rows[0] if rows else None
        if latest:
            cards=f'''<div class="cards">
<div class="card"><div class="muted">RSRP</div><div class="value">{latest["rsrp"] if latest["rsrp"] is not None else "—"} dBm</div></div>
<div class="card"><div class="muted">RSRQ</div><div class="value">{latest["rsrq"] if latest["rsrq"] is not None else "—"} dB</div></div>
<div class="card"><div class="muted">SINR</div><div class="value">{latest["sinr"] if latest["sinr"] is not None else "—"} dB</div></div>
<div class="card"><div class="muted">Band / CA</div><div class="value">{html.escape(latest["band"] or "—")}</div><div class="muted">{html.escape(latest["ca_band"] or "")}</div></div>
</div>'''
        else:
            cards='<div class="panel pad muted">No LTE interface/history detected on this router.</div>'
        table="".join(
            f'<tr><td>{html.escape(x["captured_at"])}</td><td>{html.escape(x["interface"])}</td><td>{html.escape(x["operator"] or "-")}</td>'
            f'<td>{html.escape(x["access_technology"] or "-")}</td><td>{html.escape(x["band"] or "-")}<div class="muted">{html.escape(x["ca_band"] or "")}</div></td>'
            f'<td>{x["rsrp"] if x["rsrp"] is not None else "—"}</td><td>{x["rsrq"] if x["rsrq"] is not None else "—"}</td><td>{x["sinr"] if x["sinr"] is not None else "—"}</td>'
            f'<td>{html.escape(x["cell_id"] or "-")}<div class="muted">eNB {html.escape(x["enb_id"] or "-")} · PCI {html.escape(x["phy_cell_id"] or "-")}</div></td></tr>'
            for x in rows
        ) or '<tr><td colspan="9">No LTE samples.</td></tr>'
        body=f'''<div class="panel pad"><h2>LTE history · {html.escape(router["site_name"])}</h2>
<div class="muted">{html.escape(router["model"] or "")} · signal, serving band, carrier aggregation and cell history.</div>
<div style="margin-top:12px"><a href="/operations/{router_id}"><button>Back to router</button></a><a href="/timeline/{router_id}"><button>Timeline</button></a></div></div>
{cards}<div class="panel"><table><thead><tr><th>Time</th><th>Interface</th><th>Operator</th><th>Access</th><th>Band / CA</th><th>RSRP</th><th>RSRQ</th><th>SINR</th><th>Cell</th></tr></thead><tbody>{table}</tbody></table></div>'''
        return page_func("LTE History",body,user,"operations")
