"""Opticable visual branding for Tikcentral."""

from fastapi.responses import HTMLResponse

PRETHEME = r'''
<script id="opticable-theme-init">
(function(){
  try{
    const saved=localStorage.getItem('tikcentral:theme');
    const theme=saved||(window.matchMedia&&window.matchMedia('(prefers-color-scheme: light)').matches?'light':'dark');
    document.documentElement.dataset.theme=theme;
  }catch(_){document.documentElement.dataset.theme='dark';}
})();
</script>
'''

BRAND_CSS = r'''
<style id="opticable-brand-theme">
:root{
  --oc-green:#58cf8a;--oc-green-strong:#278f5d;--oc-green-deep:#146b49;--oc-mint:#9ae7ba;
  --oc-success:#49c982;--oc-warning:#d9a743;--oc-danger:#e66c7c;
  --tc-bg:#0c120f!important;--tc-bg2:#101713!important;--tc-panel:#151d19!important;--tc-panel2:#1b2520!important;
  --tc-line:#2b3931!important;--tc-text:#f1f5f2!important;--tc-muted:#9aa8a0!important;--tc-accent:#58cf8a!important;
  --tc-accent2:#1b3b2b!important;--tc-input:#111914!important;--tc-code:#0c130f!important;--tc-shadow:0 10px 26px rgba(0,0,0,.18)!important;
}
html[data-theme="light"]{
  --tc-bg:#f4f7f5!important;--tc-bg2:#eef4f0!important;--tc-panel:#ffffff!important;--tc-panel2:#f3f7f4!important;
  --tc-line:#d9e2dc!important;--tc-text:#202722!important;--tc-muted:#6b786f!important;--tc-accent:#278f5d!important;
  --tc-accent2:#e0f2e7!important;--tc-input:#ffffff!important;--tc-code:#f3f7f4!important;--tc-shadow:0 8px 24px rgba(32,68,48,.08)!important;
}
html,body{background:var(--tc-bg)!important}body{background:linear-gradient(180deg,var(--tc-bg2) 0,var(--tc-bg) 250px)!important}
main{max-width:1840px!important;padding:16px 22px 48px!important}
.shell-head{min-height:82px!important;display:flex!important;align-items:center!important;gap:14px!important;flex-wrap:wrap!important;padding:10px 14px!important;margin:0 0 16px!important;border:1px solid var(--tc-line)!important;border-radius:16px!important;background:var(--tc-panel)!important;box-shadow:var(--tc-shadow)!important;overflow:visible!important}
.brand{flex:0 0 220px!important;width:220px!important;min-width:220px!important;max-width:220px!important;display:flex!important;align-items:center!important;justify-content:flex-start!important;overflow:visible!important}
.tc-brand-home{display:block!important;width:100%!important;height:auto!important;overflow:visible!important;text-decoration:none!important;line-height:0!important}
.tc-brand-logo{display:block!important;width:200px!important;height:auto!important;max-width:none!important;max-height:none!important;min-width:0!important;object-fit:initial!important;transform:none!important;clip-path:none!important;overflow:visible!important;image-rendering:auto!important}
.tc-logo-dark{display:block!important}.tc-logo-light{display:none!important}html[data-theme="light"] .tc-logo-dark{display:none!important}html[data-theme="light"] .tc-logo-light{display:block!important}
.tc-brand-mark{display:none!important;width:48px!important;height:auto!important;max-height:none!important;object-fit:initial!important}
.tc-brand-caption{display:none!important}
.topnav{flex:1 1 720px!important;min-width:420px!important;display:flex!important;align-items:center!important;gap:4px!important;flex-wrap:wrap!important;padding:4px!important;border-radius:11px!important;background:var(--tc-panel2)!important;overflow:visible!important}
.topnav a{padding:8px 10px!important;border-radius:8px!important;font-weight:650!important;color:var(--tc-muted)!important}.topnav a:hover{background:color-mix(in srgb,var(--oc-green) 7%,var(--tc-panel2))!important;color:var(--tc-text)!important}.topnav a.active{background:var(--tc-accent2)!important;color:var(--tc-text)!important;border-color:color-mix(in srgb,var(--oc-green) 34%,var(--tc-line))!important;box-shadow:none!important}
.account{flex:0 0 auto!important;padding:6px 7px 6px 10px!important;border:1px solid var(--tc-line)!important;border-radius:10px!important;background:var(--tc-panel2)!important}
.tc-page-tools{padding:10px 12px!important;border:1px solid var(--tc-line)!important;border-radius:12px!important;background:var(--tc-panel)!important;box-shadow:0 5px 16px rgba(0,0,0,.08)!important;overflow:visible!important}.tc-toolbar-label{color:var(--oc-green)!important}
.panel{overflow:visible!important;border-radius:14px!important;background:var(--tc-panel)!important;border-color:var(--tc-line)!important;box-shadow:var(--tc-shadow)!important}.card{overflow:hidden!important;border-radius:14px!important;background:var(--tc-panel)!important;border-color:var(--tc-line)!important;box-shadow:var(--tc-shadow)!important;padding:18px!important}.panel::after,.card::after{display:none!important}.panel:hover,.card:hover{border-color:color-mix(in srgb,var(--oc-green) 20%,var(--tc-line))!important}.cards{gap:14px!important}.card .value{color:var(--oc-green)!important;letter-spacing:-.035em;font-size:29px!important}.panel.pad>h2,.panel.pad>h3{display:flex;align-items:center;gap:9px}.panel.pad>h2::before,.panel.pad>h3::before{content:"";width:4px;height:20px;flex:0 0 4px;border-radius:99px;background:var(--oc-green);box-shadow:none}
button{border-radius:8px!important}button.primary{background:var(--oc-green-strong)!important;color:#fff!important;border-color:var(--oc-green-deep)!important;box-shadow:none!important}button.primary:hover:not(:disabled){background:#2ba567!important;box-shadow:none!important}button:not(.danger):not(.primary):hover:not(:disabled){background:color-mix(in srgb,var(--oc-green) 7%,var(--tc-panel2))!important}input,select,textarea{border-radius:8px!important}input:focus,select:focus,textarea:focus{border-color:var(--oc-green)!important;box-shadow:0 0 0 3px color-mix(in srgb,var(--oc-green) 14%,transparent)!important}
.tc-table-tools{position:relative!important;z-index:8!important;background:var(--tc-panel2)!important;border-bottom-color:var(--tc-line)!important;border-radius:13px 13px 0 0!important;overflow:visible!important}.tc-table-shell{overflow:auto!important;max-width:100%!important;border-radius:0 0 13px 13px!important}thead th{background:var(--tc-panel2)!important;border-bottom:1px solid var(--tc-line)!important}tbody tr:nth-child(even){background:color-mix(in srgb,var(--tc-panel2) 28%,transparent)}tbody tr:hover{background:color-mix(in srgb,var(--oc-green) 6%,transparent)!important}.tc-columns{z-index:40!important}.tc-columns-menu{z-index:60!important;border-color:var(--tc-line)!important;box-shadow:0 14px 36px rgba(0,0,0,.24)!important}
.dot.online{background:var(--oc-success)!important;box-shadow:0 0 0 3px color-mix(in srgb,var(--oc-success) 13%,transparent)}.dot.offline{background:#7e8c84!important}.tc-status{display:inline-flex;align-items:center;gap:6px;padding:4px 9px;border-radius:999px;font-size:11px;font-weight:750;letter-spacing:.02em;border:1px solid transparent;line-height:1.2;white-space:nowrap}.tc-status::before{content:"";width:6px;height:6px;border-radius:50%;background:currentColor}.tc-status-ok{color:#55d991;background:color-mix(in srgb,#35c979 10%,transparent);border-color:color-mix(in srgb,#35c979 24%,transparent)}html[data-theme="light"] .tc-status-ok{color:#137b48;background:#e8f7ef;border-color:#bde8d0}.tc-status-warn{color:#edba59;background:color-mix(in srgb,#e4aa39 10%,transparent);border-color:color-mix(in srgb,#e4aa39 24%,transparent)}html[data-theme="light"] .tc-status-warn{color:#976410;background:#fff7e5;border-color:#f1ddb3}.tc-status-bad{color:#ef7b89;background:color-mix(in srgb,#e95f73 10%,transparent);border-color:color-mix(in srgb,#e95f73 24%,transparent)}html[data-theme="light"] .tc-status-bad{color:#b5364a;background:#fff0f2;border-color:#f0c3ca}.tc-status-neutral{color:var(--tc-muted);background:var(--tc-panel2);border-color:var(--tc-line)}
.login{max-width:460px!important;margin-top:56px!important}code{padding:2px 5px;border-radius:5px;background:color-mix(in srgb,var(--oc-green) 5%,var(--tc-code))}pre{box-shadow:none!important}::-webkit-scrollbar{height:10px;width:10px}::-webkit-scrollbar-track{background:transparent}::-webkit-scrollbar-thumb{background:color-mix(in srgb,var(--oc-green) 20%,var(--tc-line));border-radius:99px;border:2px solid transparent;background-clip:padding-box}
@media(max-width:1180px){.brand{flex-basis:190px!important;width:190px!important;min-width:190px!important;max-width:190px!important}.tc-brand-logo{width:170px!important;height:auto!important}.topnav{min-width:360px!important}}
@media(max-width:820px){main{padding:10px 10px 36px!important}.shell-head{position:relative!important;min-height:auto!important;padding:10px!important}.brand{flex:0 0 54px!important;width:54px!important;min-width:54px!important;max-width:54px!important}.tc-brand-logo{display:none!important}.tc-brand-mark{display:block!important;width:48px!important;height:auto!important}.topnav{order:3;flex:1 1 100%!important;min-width:0!important;overflow:auto!important;flex-wrap:nowrap!important}.topnav a{white-space:nowrap!important}.account{margin-left:auto!important}}
@media(max-width:560px){.account span{display:none}.cards{grid-template-columns:1fr!important}}
</style>
'''

BRAND_JS = r'''
<script id="opticable-brand-js">
(function(){
  const stateMap={'online':'ok','healthy':'ok','passed':'ok','success':'ok','enabled':'ok','ready':'ok','connected':'ok','commissioned':'ok','matches baseline':'ok','warning':'warn','partial':'warn','degraded':'warn','pending':'warn','queued':'warn','running':'warn','rebooting':'warn','routerboot required':'warn','drift':'warn','drift detected':'warn','failed':'bad','error':'bad','critical':'bad','offline':'bad','disabled':'neutral','not checked':'neutral','not_checked':'neutral','none':'neutral','unknown':'neutral'};
  function syncThemeColor(){const meta=document.querySelector('meta[name="theme-color"]');if(meta)meta.content=document.documentElement.dataset.theme==='light'?'#f4f7f5':'#101713';}
  function brandStatuses(){syncThemeColor();document.querySelectorAll('td').forEach(td=>{if(td.dataset.ocStatus==='1'||td.children.length)return;const raw=(td.textContent||'').trim();const tone=stateMap[raw.toLowerCase()];if(!tone)return;td.dataset.ocStatus='1';const s=document.createElement('span');s.className='tc-status tc-status-'+tone;s.textContent=raw;td.textContent='';td.appendChild(s);});}
  const observer=new MutationObserver(m=>{if(m.some(x=>x.attributeName==='data-theme'))syncThemeColor();});observer.observe(document.documentElement,{attributes:true});if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',brandStatuses);else brandStatuses();
})();
</script>
'''

BRAND_HTML = '''<div class="brand"><a class="tc-brand-home" href="/" aria-label="Opticable Tikcentral home"><img class="tc-brand-logo tc-logo-light" src="/static/opticable-logo-light.svg?v=5" alt="Opticable"><img class="tc-brand-logo tc-logo-dark" src="/static/opticable-logo-dark.svg?v=5" alt="Opticable"><img class="tc-brand-mark" src="/static/opticable-icon.png?v=5" alt="Opticable"></a></div>'''


def enhance_response(response: HTMLResponse) -> HTMLResponse:
    text = response.body.decode("utf-8")
    old = '<div class="brand"><h1>Tikcentral</h1><div class="sub">MikroTik remote management</div></div>'
    text = text.replace(old, BRAND_HTML)
    if '/static/opticable-icon.png' not in text.split('</head>', 1)[0]:
        head = PRETHEME + '<link rel="icon" type="image/png" href="/static/opticable-icon.png?v=5"><meta name="theme-color" content="#101713">' + BRAND_CSS
        text = text.replace('</head>', head + '</head>', 1)
    if 'opticable-brand-js' not in text:text = text.replace('</body>', BRAND_JS + '</body>', 1)
    headers = {k:v for k,v in response.headers.items() if k.lower() not in {'content-length','content-type'}}
    return HTMLResponse(text, status_code=response.status_code, headers=headers)
