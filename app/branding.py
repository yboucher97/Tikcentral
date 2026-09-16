"""Opticable visual branding for Tikcentral."""

from fastapi.responses import HTMLResponse

BRAND_CSS = r'''
<style id="opticable-brand-theme">
:root{
  --oc-green:#59cf8b;
  --oc-green-strong:#24925d;
  --oc-green-deep:#0f6b48;
  --oc-mint:#9ae7ba;
  --oc-charcoal:#252b28;
  --oc-success:#4ed88d;
  --oc-warning:#e7b553;
  --oc-danger:#ef7282;
  --tc-bg:#0b110e!important;
  --tc-bg2:#101a15!important;
  --tc-panel:#141f19!important;
  --tc-panel2:#1b2a22!important;
  --tc-line:#294237!important;
  --tc-text:#f1f7f3!important;
  --tc-muted:#98aa9f!important;
  --tc-accent:#59cf8b!important;
  --tc-accent2:#173d2b!important;
  --tc-input:#101a15!important;
  --tc-code:#09100c!important;
  --tc-shadow:0 18px 44px rgba(0,0,0,.23)!important;
}
html[data-theme="light"]{
  --tc-bg:#f3f8f5!important;
  --tc-bg2:#eaf4ee!important;
  --tc-panel:#ffffff!important;
  --tc-panel2:#f0f7f3!important;
  --tc-line:#d5e5db!important;
  --tc-text:#202823!important;
  --tc-muted:#68786f!important;
  --tc-accent:#238d59!important;
  --tc-accent2:#dff3e7!important;
  --tc-input:#ffffff!important;
  --tc-code:#f2f7f4!important;
  --tc-shadow:0 14px 38px rgba(28,65,45,.09)!important;
}
html,body{background:var(--tc-bg)!important}
body{
  background:
    radial-gradient(circle at 12% -10%,color-mix(in srgb,var(--oc-green) 16%,transparent) 0,transparent 28%),
    radial-gradient(circle at 92% 3%,color-mix(in srgb,var(--oc-green-deep) 10%,transparent) 0,transparent 24%),
    linear-gradient(180deg,var(--tc-bg2) 0,var(--tc-bg) 310px)!important;
}
main{max-width:1840px!important;padding-left:24px!important;padding-right:24px!important}
.shell-head{
  min-height:76px;
  border:1px solid color-mix(in srgb,var(--oc-green) 16%,var(--tc-line))!important;
  border-radius:18px!important;
  padding:11px 14px!important;
  margin:0 0 16px!important;
  box-shadow:0 12px 34px rgba(0,0,0,.12)!important;
  background:linear-gradient(135deg,color-mix(in srgb,var(--tc-panel) 94%,var(--oc-green) 6%),var(--tc-panel))!important;
}
.brand{min-width:205px!important;display:flex!important;align-items:center!important}
.tc-brand-home{display:flex;align-items:center;text-decoration:none!important;min-height:52px}
.tc-brand-logo{width:180px;height:48px;object-fit:contain;object-position:left center;display:block}
.tc-logo-dark{display:block}.tc-logo-light{display:none}.tc-brand-mark{display:none;width:44px;height:44px;object-fit:contain}
html[data-theme="light"] .tc-logo-dark{display:none}html[data-theme="light"] .tc-logo-light{display:block}
.tc-brand-caption{font-size:10px;letter-spacing:.12em;text-transform:uppercase;color:var(--tc-muted);margin-left:12px;white-space:nowrap}
.topnav{padding:5px;border-radius:13px;background:color-mix(in srgb,var(--tc-panel2) 62%,transparent)!important}
.topnav a{font-weight:650!important;letter-spacing:.005em;padding:9px 12px!important}
.topnav a.active{background:linear-gradient(135deg,color-mix(in srgb,var(--oc-green) 24%,var(--tc-panel2)),var(--tc-accent2))!important;border-color:color-mix(in srgb,var(--oc-green) 42%,var(--tc-line))!important;box-shadow:0 4px 14px color-mix(in srgb,var(--oc-green) 14%,transparent)}
.account{padding:6px 7px 6px 12px;border:1px solid var(--tc-line);border-radius:12px;background:color-mix(in srgb,var(--tc-panel2) 78%,transparent)}
.tc-page-tools{border-color:color-mix(in srgb,var(--oc-green) 18%,var(--tc-line))!important;background:linear-gradient(90deg,color-mix(in srgb,var(--tc-panel) 96%,var(--oc-green) 4%),var(--tc-panel))!important}
.tc-toolbar-label{color:var(--oc-green)!important}
.panel,.card{position:relative;overflow:hidden!important}
.panel::after,.card::after{content:"";position:absolute;left:0;right:0;top:0;height:1px;background:linear-gradient(90deg,transparent,color-mix(in srgb,var(--oc-green) 46%,transparent),transparent);pointer-events:none}
.panel:hover,.card:hover{border-color:color-mix(in srgb,var(--oc-green) 30%,var(--tc-line))!important}
.cards{gap:16px!important}
.card{padding:19px!important;background:linear-gradient(145deg,var(--tc-panel),color-mix(in srgb,var(--tc-panel2) 76%,var(--tc-panel)))!important}
.card .value{color:var(--oc-green)!important;letter-spacing:-.04em;font-size:30px!important}
.panel.pad>h2,.panel.pad>h3{display:flex;align-items:center;gap:9px}
.panel.pad>h2::before,.panel.pad>h3::before{content:"";width:4px;height:22px;border-radius:99px;background:linear-gradient(180deg,var(--oc-mint),var(--oc-green-deep));box-shadow:0 0 16px color-mix(in srgb,var(--oc-green) 30%,transparent)}
button.primary{background:linear-gradient(135deg,var(--oc-green-strong),var(--oc-green-deep))!important;color:#fff!important;border-color:color-mix(in srgb,var(--oc-green) 70%,var(--oc-green-deep))!important;box-shadow:0 7px 18px rgba(24,119,74,.2)}
button.primary:hover:not(:disabled){background:linear-gradient(135deg,#2aa969,#11734c)!important;box-shadow:0 9px 24px rgba(24,119,74,.28)}
button:not(.danger):not(.primary):hover:not(:disabled){background:color-mix(in srgb,var(--oc-green) 9%,var(--tc-panel2))!important}
input:focus,select:focus,textarea:focus{border-color:var(--oc-green)!important;box-shadow:0 0 0 3px color-mix(in srgb,var(--oc-green) 16%,transparent)!important}
thead th{background:color-mix(in srgb,var(--tc-panel) 94%,var(--oc-green) 6%)!important;border-bottom:1px solid color-mix(in srgb,var(--oc-green) 18%,var(--tc-line))!important}
tbody tr:nth-child(even){background:color-mix(in srgb,var(--tc-panel2) 22%,transparent)}
tbody tr:hover{background:color-mix(in srgb,var(--oc-green) 8%,transparent)!important}
.tc-table-tools{background:linear-gradient(90deg,color-mix(in srgb,var(--tc-panel2) 88%,var(--oc-green) 4%),var(--tc-panel2))!important}
.tc-columns-menu{border-color:color-mix(in srgb,var(--oc-green) 24%,var(--tc-line))!important}
.dot.online{background:var(--oc-success)!important;box-shadow:0 0 0 4px color-mix(in srgb,var(--oc-success) 14%,transparent),0 0 13px color-mix(in srgb,var(--oc-success) 42%,transparent)}
.dot.offline{background:#7e8c84!important}
.tc-status{display:inline-flex;align-items:center;gap:6px;padding:4px 9px;border-radius:999px;font-size:11px;font-weight:750;letter-spacing:.025em;border:1px solid transparent;line-height:1.2;white-space:nowrap}
.tc-status::before{content:"";width:6px;height:6px;border-radius:50%;background:currentColor;box-shadow:0 0 8px currentColor}
.tc-status-ok{color:#55d991;background:color-mix(in srgb,#35c979 11%,transparent);border-color:color-mix(in srgb,#35c979 25%,transparent)}
html[data-theme="light"] .tc-status-ok{color:#137b48;background:#e8f7ef;border-color:#bde8d0}
.tc-status-warn{color:#f0bd5d;background:color-mix(in srgb,#e4aa39 11%,transparent);border-color:color-mix(in srgb,#e4aa39 27%,transparent)}
html[data-theme="light"] .tc-status-warn{color:#976410;background:#fff7e5;border-color:#f1ddb3}
.tc-status-bad{color:#f17d8c;background:color-mix(in srgb,#e95f73 11%,transparent);border-color:color-mix(in srgb,#e95f73 25%,transparent)}
html[data-theme="light"] .tc-status-bad{color:#b5364a;background:#fff0f2;border-color:#f0c3ca}
.tc-status-neutral{color:var(--tc-muted);background:var(--tc-panel2);border-color:var(--tc-line)}
code{padding:2px 5px;border-radius:5px;background:color-mix(in srgb,var(--oc-green) 6%,var(--tc-code))}
pre{box-shadow:inset 0 1px 0 color-mix(in srgb,var(--oc-green) 10%,transparent)}
::-webkit-scrollbar{height:10px;width:10px}::-webkit-scrollbar-track{background:transparent}::-webkit-scrollbar-thumb{background:color-mix(in srgb,var(--oc-green) 26%,var(--tc-line));border-radius:99px;border:2px solid transparent;background-clip:padding-box}
@media(max-width:1150px){.tc-brand-caption{display:none}.brand{min-width:180px!important}.tc-brand-logo{width:160px;height:43px}}
@media(max-width:720px){main{padding-left:10px!important;padding-right:10px!important}.shell-head{border-radius:14px!important}.tc-brand-logo{display:none!important}.tc-brand-mark{display:block}.brand{min-width:52px!important}.topnav{width:calc(100% - 70px)}.account{width:100%!important}}
</style>
'''

BRAND_JS = r'''
<script id="opticable-brand-js">
(function(){
  const stateMap={
    'online':'ok','healthy':'ok','passed':'ok','success':'ok','enabled':'ok','ready':'ok','connected':'ok','commissioned':'ok','matches baseline':'ok',
    'warning':'warn','partial':'warn','degraded':'warn','pending':'warn','queued':'warn','running':'warn','rebooting':'warn','routerboot required':'warn','drift':'warn','drift detected':'warn',
    'failed':'bad','error':'bad','critical':'bad','offline':'bad','disabled':'neutral','not checked':'neutral','not_checked':'neutral','none':'neutral','unknown':'neutral'
  };
  function brandStatuses(){
    document.querySelectorAll('td').forEach(td=>{
      if(td.dataset.ocStatus==='1'||td.children.length)return;
      const raw=(td.textContent||'').trim(); const key=raw.toLowerCase(); const tone=stateMap[key];
      if(!tone)return;
      td.dataset.ocStatus='1';
      const s=document.createElement('span');s.className='tc-status tc-status-'+tone;s.textContent=raw;td.textContent='';td.appendChild(s);
    });
    document.querySelectorAll('tbody tr').forEach(tr=>{
      if(tr.cells.length===1&&tr.cells[0].colSpan>1&&/^no\s/i.test((tr.textContent||'').trim())) tr.classList.add('tc-empty-row');
    });
  }
  if(document.readyState==='loading') document.addEventListener('DOMContentLoaded',brandStatuses); else brandStatuses();
})();
</script>
'''

BRAND_HTML = '''<div class="brand"><a class="tc-brand-home" href="/" aria-label="Opticable Tikcentral home"><img class="tc-brand-logo tc-logo-light" src="/static/opticable-logo-light.png" alt="Opticable"><img class="tc-brand-logo tc-logo-dark" src="/static/opticable-logo-dark.png" alt="Opticable"><img class="tc-brand-mark" src="/static/opticable-icon.png" alt="Opticable"><span class="tc-brand-caption">Network Operations</span></a></div>'''


def enhance_response(response: HTMLResponse) -> HTMLResponse:
    text = response.body.decode("utf-8")
    old = '<div class="brand"><h1>Tikcentral</h1><div class="sub">MikroTik remote management</div></div>'
    text = text.replace(old, BRAND_HTML)
    if '/static/opticable-icon.png' not in text.split('</head>', 1)[0]:
        head = '<link rel="icon" type="image/png" href="/static/opticable-icon.png"><meta name="theme-color" content="#101a15">' + BRAND_CSS
        text = text.replace('</head>', head + '</head>', 1)
    if 'opticable-brand-js' not in text:
        text = text.replace('</body>', BRAND_JS + '</body>', 1)
    headers = {k:v for k,v in response.headers.items() if k.lower() not in {'content-length','content-type'}}
    return HTMLResponse(text, status_code=response.status_code, headers=headers)
