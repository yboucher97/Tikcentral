"""Render realistic pages against temporary sample data for browser regressions."""
import os
import sys
import tempfile
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
tmp = tempfile.TemporaryDirectory()
os.environ.update(DB_PATH=tmp.name+'/preview.db', ADMIN_API_KEY='preview-only', WG_SERVER_PUBLIC_KEY='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=', WG_ENDPOINT='preview.invalid:51820', PUBLIC_HOSTNAME='tikcentral.example.invalid')
from app import main as core, ui, portal
from app.final import app
from starlette.requests import Request
user = {'id': 1, 'email': 'operator@example.invalid', 'role': 'admin'}
core.require_web_admin = lambda req: user
core.require_web_role = lambda req, role='viewer': user
core.wireguard_peers = lambda: {}
from app import router_exec
router_exec.read = lambda *a, **kw: ''
with core.db() as conn:
    for i,(site,ident,model) in enumerate([('Montréal · Office','MTL-Office-01','RB5009UG+S+'),('Laval · Warehouse','LAV-Warehouse-01','CCR2004-16G-2S+'),('Blainville · Pharmacy','BLV-Pharmacy-01','hAP ax³'),('Québec · Construction','QC-Jobsite-01','LHG LTE18')],1):
        conn.execute('INSERT INTO routers(id,site_name,identity,serial,model,public_key,vpn_ip,public_winbox_port,enabled,created_at,routeros_version,lifecycle_state) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',(i,site,ident,'SAMPLE-'+str(i),model,'sample-key-'+str(i),'10.250.1.'+str(i),23000+i,1,'2026-09-19T12:15:00+00:00','7.20.1','production'))
        if i != 4:
            conn.execute('INSERT INTO router_access_state(router_id,checked_at,wg_online,management_ok) VALUES(?,?,?,?)', (i, '2026-09-19T12:15:00+00:00', 1 if i != 2 else 0, 1 if i != 2 else 0))


out = Path(sys.argv[1])
out.mkdir(parents=True, exist_ok=True)
for path,name in [('/routers','routers'),('/','dashboard'),('/operations/1','router'),('/checks','checks')]:
    req = Request({'type':'http','method':'GET','path':path,'query_string':b'','headers':[]})
    if path=='/routers': response=portal.routers_page(req)
    elif path=='/': response=core.dashboard(req)
    elif path=='/operations/1':
        route=next(r for r in app.routes if getattr(r,'path','')=='/operations/{router_id}' and 'GET' in r.methods)
        response=route.endpoint(1,req)
    else:
        response=ui.page('Table checks','<div class="panel"><table><thead><tr><th>Time</th><th>Level</th><th>Message</th></tr></thead><tbody><tr><td>2026-09-19T12:15:30+00:00</td><td>warning</td><td>WAN recovered<div class="muted">Backup link restored</div></td></tr><tr><td>2026-09-19T12:16:30+00:00</td><td>ok</td><td>Normal</td></tr></tbody></table></div><div class="panel"><table><thead><tr><th>Time</th><th>Event</th></tr></thead><tbody><tr><td colspan="2">No events.</td></tr></tbody></table></div><div class="panel"><table style="min-width:0"><tbody><tr><td>Hostname</td><td><code>router.example.invalid</code></td></tr></tbody></table></div>',user,'alerts')
    (out / (name+'.html')).write_bytes(response.body)

# Capture a data-rich router as well as the empty/first-enrollment state above.
with core.db() as conn:
    conn.execute("INSERT INTO router_events(router_id,event_at,category,severity,summary,details) VALUES(1,'2026-09-19T12:16:30+00:00','network','warning','WAN link recovered','Gateway reachable again')")
route = next(r for r in app.routes if getattr(r, 'path', '') == '/operations/{router_id}' and 'GET' in r.methods)
req = Request({'type':'http','method':'GET','path':'/operations/1','query_string':b'','headers':[]})
for role in ('admin', 'technician', 'viewer'):
    user['role'] = role
    (out / ('router-'+role+'.html')).write_bytes(route.endpoint(1, req).body)
(out / 'navigation.json').write_text(json.dumps({
    role: [href for key, href, _ in ui.NAV if role == 'admin' or key not in {'users', 'settings', 'ssh', 'enroll'}]
    for role in ('admin', 'technician', 'viewer')
}))
print('Rendered offline UI fixtures', flush=True)
