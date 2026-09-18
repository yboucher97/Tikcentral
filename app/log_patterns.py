"""Normalize and aggregate RouterOS log patterns without retaining raw sensitive logs."""

import hashlib, html, re
from collections import Counter
from datetime import datetime, timezone
from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse
from app import events, main as core, migrations, router_exec

IP_RE=re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
MAC_RE=re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b")
NUM_RE=re.compile(r"\b\d{2,}\b")

def _now():return datetime.now(timezone.utc).isoformat()
def _normalize(line):
    s=router_exec.sanitize(line,1200)
    s=re.sub(r'(?i)\b(secret|community|preshared[-_ ]?key|api[-_ ]?key)\s*[=:]\s*("[^"]*"|[^\s;]+)',r'\1=<redacted>',s)
    s=re.sub(r"^\s*(?:[a-z]{3}/\d{1,2}/\d{4}\s+)?\d{1,2}:\d{2}:\d{2}\s+","",s,flags=re.I)
    s=re.sub(r"^\s*[a-z]{3}/\d{1,2}\s+\d{1,2}:\d{2}:\d{2}\s+","",s,flags=re.I)
    s=IP_RE.sub("<ip>",s); s=MAC_RE.sub("<mac>",s); s=NUM_RE.sub("<n>",s)
    s=re.sub(r"\s+"," ",s).strip()
    return s[-500:]
def _category(s):
    low=s.lower()
    for name,keys in (("interface",("link down","link up","ether")),("dhcp",("dhcp","lease")),("pppoe",("pppoe","ppp")),("lte",("lte","cellular")),("dns",("dns","resolve")),("auth",("login","authentication","user")),("route",("route","gateway")),("firewall",("firewall","drop","input"))):
        if any(k in low for k in keys): return name
    return "other"
def _severity(s):
    low=s.lower()
    if any(k in low for k in ("error","failed","failure","critical","timeout")): return "warning"
    return "info"

def collect(router_id:int,force=False):
    migrations.migrate()
    with core.db() as conn:
        r=conn.execute("SELECT id,site_name,vpn_ip,enabled,lifecycle_state FROM routers WHERE id=?",(router_id,)).fetchone()
        last=conn.execute("SELECT captured_at FROM router_log_patterns WHERE router_id=? ORDER BY id DESC LIMIT 1",(router_id,)).fetchone()
    if not r or not r["enabled"] or (r["lifecycle_state"] or "production")=="retired":return None
    if last and not force:
        try:
            if (datetime.now(timezone.utc)-datetime.fromisoformat(last["captured_at"])).total_seconds()<3600:return 0
        except Exception:pass
    raw=router_exec.read(r["vpn_ip"],"/log print without-paging",timeout=35,label="Log pattern analysis")
    patterns=[]
    for line in raw.splitlines()[-1000:]:
        n=_normalize(line)
        if n:patterns.append(n)
    counts=Counter(patterns); captured=_now()
    with core.db() as conn:
        previous={x["pattern_hash"]:x["occurrences"] for x in conn.execute("SELECT pattern_hash,occurrences FROM router_log_patterns WHERE router_id=? AND captured_at=(SELECT MAX(captured_at) FROM router_log_patterns WHERE router_id=?)",(router_id,router_id)).fetchall()}
        for pattern,count in counts.most_common(100):
            h=hashlib.sha256(pattern.encode()).hexdigest()
            cat=_category(pattern); sev=_severity(pattern)
            conn.execute("""INSERT INTO router_log_patterns(router_id,captured_at,pattern_hash,category,severity,normalized_pattern,sample,occurrences)
                            VALUES(?,?,?,?,?,?,?,?)""",(router_id,captured,h,cat,sev,pattern,pattern,count))
            prior_count=previous.get(h,0)
            if sev=="warning" and count>=10 and (prior_count==0 or count>=max(10,prior_count*3)):
                title="Router log pattern detected" if prior_count==0 else "Router log pattern increased"
                events.record(router_id,"log-pattern",f"{title}: {cat}",f"{count} occurrences · {pattern[:300]}","warning")
        conn.execute("""DELETE FROM router_log_patterns WHERE router_id=? AND id NOT IN
                        (SELECT id FROM router_log_patterns WHERE router_id=? ORDER BY id DESC LIMIT 10000)""",(router_id,router_id))
    return len(counts)

def register(app,page_func):
    @app.get("/log-patterns/{router_id}",response_class=HTMLResponse)
    def page(router_id:int,request:Request):
        user=core.require_web_admin(request)
        if not user:return RedirectResponse("/login",303)
        try:collect(router_id)
        except Exception:pass
        with core.db() as conn:
            r=conn.execute("SELECT site_name FROM routers WHERE id=?",(router_id,)).fetchone()
            t=conn.execute("SELECT MAX(captured_at) t FROM router_log_patterns WHERE router_id=?",(router_id,)).fetchone()["t"]
            rows=conn.execute("SELECT * FROM router_log_patterns WHERE router_id=? AND captured_at=? ORDER BY occurrences DESC LIMIT 100",(router_id,t or "")).fetchall() if t else []
        if not r:return RedirectResponse("/operations",303)
        rendered="".join(f'<tr><td>{html.escape(x["severity"])}</td><td>{html.escape(x["category"])}</td><td>{x["occurrences"]}</td><td><code>{html.escape(x["normalized_pattern"])}</code></td></tr>' for x in rows) or '<tr><td colspan="4">No log patterns collected.</td></tr>'
        body=f'''<div class="panel pad"><h2>Router log patterns · {html.escape(r["site_name"])}</h2><div class="muted">Raw logs are normalized and redacted before storage. IPs, MACs and changing numeric identifiers are generalized so recurring patterns can be grouped.</div></div>
<div class="panel"><table><thead><tr><th>Level</th><th>Category</th><th>Count</th><th>Normalized pattern</th></tr></thead><tbody>{rendered}</tbody></table></div>'''
        return page_func("Log Patterns",body,user,"operations")
