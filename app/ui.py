"""Single HTML renderer for all Tikcentral pages."""

import html

from fastapi.responses import HTMLResponse

from app import settings
from app.ui_time import localize_html_iso_timestamps

NAV_GROUPS = [
    ("Overview", [
        ("dashboard", "/", "Dashboard"),
        ("alerts", "/alerts", "Alerts"),
    ]),
    ("Fleet", [
        ("routers", "/routers", "Routers"),
        ("fleet-search", "/fleet-search", "Fleet search"),
        ("customers", "/customers", "Customers"),
        ("cross-site-anomalies", "/cross-site-anomalies", "Cross-site"),
        ("model-capabilities", "/model-capabilities", "Model capabilities"),
        ("hardware-lifecycle", "/hardware-lifecycle", "Hardware lifecycle"),
        ("identity-collisions", "/identity-collisions", "Identity collisions"),
    ]),
    ("Operations", [
        ("operations", "/operations", "Router operations"),
        ("guardian", "/guardian", "Guardian"),
        ("reliability", "/reliability", "Reliability"),
        ("compliance", "/compliance", "Compliance"),
        ("rescue", "/rescue", "Rescue"),
        ("automation", "/automation", "Automation"),
        ("ssh", "/ssh", "Web SSH"),
    ]),
    ("Changes", [
        ("changes", "/changes", "Changes"),
        ("change-calendar", "/change-calendar", "Calendar"),
        ("maintenance-automation", "/maintenance-automation", "Post-change"),
        ("upgrade-campaigns", "/upgrade-campaigns", "Upgrades"),
        ("replacements", "/replacements", "Replacements"),
        ("lifecycle", "/lifecycle", "Lifecycle"),
    ]),
    ("Intelligence", [
        ("config-search", "/config-search", "Config search"),
        ("audit", "/audit", "Router audit"),
        ("operator-audit", "/operator-audit", "Operator audit"),
    ]),
    ("Administration", [
        ("enroll", "/enroll", "Enroll router"),
        ("retention", "/retention", "Retention"),
        ("system-health", "/system-health", "System health"),
        ("database-health", "/database-health", "Database health"),
        ("users", "/admin/users", "Users"),
        ("settings", "/settings", "Settings"),
    ]),
]

NAV = [item for _, items in NAV_GROUPS for item in items]
NAV_CATEGORY = {key: group for group, items in NAV_GROUPS for key, _, _ in items}

def _infer_active(title: str) -> str:
    t = (title or "").lower()
    for key, _, label in NAV:
        if label.lower() in t:
            return key
    if "password" in t:
        return "settings"
    return "dashboard" if t == "dashboard" else ""


CSS = r'''
:root{
 --bg:#0b100d;--surface:#111713;--surface2:#161e19;--surface3:#1d2721;--line:#29352e;
 --text:#eef3ef;--muted:#94a099;--accent:#45bd7a;--accent2:#23885a;--accent-soft:color-mix(in srgb,#45bd7a 13%,transparent);
 --danger:#e66d7c;--warn:#d7a84d;--ok:#56ce8a;--input:#0e1511;--shadow:0 10px 30px rgba(0,0,0,.20);
 --sidebar:252px;--radius:12px;--content:1640px;
}
html[data-theme="light"]{
 --bg:#f3f6f4;--surface:#ffffff;--surface2:#f7f9f8;--surface3:#eef3f0;--line:#d9e1dc;
 --text:#1d2520;--muted:#69766f;--accent:#21865a;--accent2:#166d48;--accent-soft:color-mix(in srgb,#21865a 11%,transparent);
 --danger:#bf4052;--warn:#986813;--ok:#21865a;--input:#fff;--shadow:0 8px 24px rgba(28,58,40,.08)
}
*{box-sizing:border-box}
html,body{margin:0;min-height:100%;background:var(--bg);color:var(--text);font:14px/1.48 Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
body{background:var(--bg)}
a{color:var(--accent);text-decoration:none}a:hover{color:color-mix(in srgb,var(--accent) 82%,white)}
button,input,select,textarea{font:inherit}
button{border:1px solid var(--line);background:var(--surface2);color:var(--text);border-radius:8px;padding:8px 11px;cursor:pointer;transition:.14s ease}
button:hover:not(:disabled){background:var(--surface3);border-color:color-mix(in srgb,var(--accent) 34%,var(--line))}
button:disabled{opacity:.48;cursor:not-allowed}
.primary{background:var(--accent2)!important;border-color:var(--accent2)!important;color:#fff!important}
.danger{background:color-mix(in srgb,var(--danger) 11%,var(--surface2))!important;border-color:color-mix(in srgb,var(--danger) 45%,var(--line))!important;color:var(--danger)!important}
input,select,textarea{background:var(--input);color:var(--text);border:1px solid var(--line);border-radius:8px;padding:9px 10px;min-height:36px}
input:focus,select:focus,textarea:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px color-mix(in srgb,var(--accent) 14%,transparent)}
textarea.script{width:100%;min-height:60vh;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}code{background:var(--surface3);padding:2px 5px;border-radius:5px}
h1,h2,h3{line-height:1.25}h1{font-size:24px}h2{font-size:18px}h3{font-size:14px}
.muted,.sub{color:var(--muted)}.inline{display:flex;gap:9px;align-items:center;flex-wrap:wrap}
.error{background:color-mix(in srgb,var(--danger) 10%,var(--surface));border:1px solid color-mix(in srgb,var(--danger) 40%,var(--line));padding:11px 13px;border-radius:10px}

.tc-shell{display:grid;grid-template-columns:var(--sidebar) minmax(0,1fr);min-height:100vh}
.tc-sidebar{position:sticky;top:0;height:100vh;overflow:auto;background:var(--surface);border-right:1px solid var(--line);padding:16px 12px 18px;z-index:30}
.tc-brand{display:flex;align-items:center;height:52px;padding:0 8px 12px;margin-bottom:8px;border-bottom:1px solid var(--line)}
.tc-logo{display:block;width:182px;max-height:38px;object-fit:contain;object-position:left center}.tc-logo-light{display:none}.tc-logo-dark{display:block}
html[data-theme="light"] .tc-logo-dark{display:none}html[data-theme="light"] .tc-logo-light{display:block}
.tc-icon{display:none;width:34px;height:34px}
.tc-nav-group{margin:8px 0 3px}.tc-nav-label{list-style:none;cursor:pointer;padding:7px 10px;color:var(--muted);font-size:10px;letter-spacing:.10em;text-transform:uppercase;font-weight:800;border-radius:7px}.tc-nav-label::-webkit-details-marker{display:none}.tc-nav-label:after{content:"›";float:right;font-size:14px;line-height:10px;transition:transform .14s}.tc-nav-group[open]>.tc-nav-label:after{transform:rotate(90deg)}.tc-nav-label:hover{background:var(--surface2);color:var(--text)}
.tc-nav{display:grid;gap:2px;margin-top:2px}.tc-nav a{display:flex;align-items:center;min-height:36px;padding:8px 10px;border-radius:8px;color:var(--muted);font-weight:650}
.tc-nav a:hover{background:var(--surface2);color:var(--text)}.tc-nav a.active{background:var(--accent-soft);color:var(--text);box-shadow:inset 3px 0 0 var(--accent)}
.tc-sidebar-foot{margin-top:18px;padding:12px 8px 0;border-top:1px solid var(--line);font-size:12px;color:var(--muted)}
.tc-main{min-width:0}.tc-topbar{position:sticky;top:0;z-index:25;height:64px;display:flex;align-items:center;gap:12px;padding:0 22px;background:color-mix(in srgb,var(--bg) 88%,transparent);backdrop-filter:blur(12px);border-bottom:1px solid var(--line)}
.tc-menu-btn{display:none}.tc-page-meta{min-width:0;flex:1}.tc-page-title{font-size:17px;font-weight:780;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.tc-breadcrumb{font-size:11px;color:var(--muted);margin-top:2px}
.tc-top-actions{display:flex;align-items:center;gap:8px}.tc-command-btn{min-width:220px;text-align:left;color:var(--muted);display:flex;justify-content:space-between;gap:12px}.tc-kbd{font-size:10px;border:1px solid var(--line);background:var(--surface3);padding:2px 5px;border-radius:5px;color:var(--muted)}
.tc-account{position:relative}.tc-account>button{max-width:210px}.tc-account-menu{display:none;position:absolute;right:0;top:calc(100% + 7px);width:240px;background:var(--surface);border:1px solid var(--line);border-radius:10px;box-shadow:var(--shadow);padding:8px;z-index:80}.tc-account.open .tc-account-menu{display:block}.tc-account-menu a,.tc-account-menu form{display:block}.tc-account-menu button{width:100%;text-align:left;border:0;background:transparent}
.tc-content{max-width:var(--content);margin:0 auto;padding:22px 24px 56px}
.tc-page-tools{display:flex;gap:8px;align-items:center;margin-bottom:16px}.tc-page-tools input{flex:1;max-width:420px}.tc-page-tools .hint{margin-left:auto;color:var(--muted);font-size:11px}

.panel,.card{background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);box-shadow:none;margin-bottom:14px}
.panel{overflow:visible}.panel.pad,.pad{padding:16px}.panel>table:first-child{border-radius:var(--radius)}
.panel.pad>h2,.panel.pad>h3{margin-bottom:9px}.panel.pad>h2:before,.panel.pad>h3:before{display:none}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:10px;margin-bottom:14px}.card{padding:14px;overflow:hidden;margin-bottom:0}.card .value{font-size:25px;font-weight:760;letter-spacing:-.025em;color:var(--text)}
.tc-section-title{display:flex;align-items:center;justify-content:space-between;gap:12px;margin:22px 0 10px}.tc-section-title h2{margin:0}.tc-section-title .muted{font-size:12px}

.badge,.tc-status{display:inline-flex;align-items:center;gap:6px;padding:4px 8px;border-radius:999px;font-size:11px;font-weight:750;border:1px solid var(--line);white-space:nowrap}
.tc-status.ok{color:var(--ok);background:color-mix(in srgb,var(--ok) 10%,transparent);border-color:color-mix(in srgb,var(--ok) 35%,var(--line))}
.tc-status.warn{color:var(--warn);background:color-mix(in srgb,var(--warn) 10%,transparent);border-color:color-mix(in srgb,var(--warn) 35%,var(--line))}
.tc-status.bad{color:var(--danger);background:color-mix(in srgb,var(--danger) 10%,transparent);border-color:color-mix(in srgb,var(--danger) 35%,var(--line))}
.tc-status-dot{width:7px;height:7px;border-radius:50%;background:currentColor;display:inline-block}
.tc-health-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(165px,1fr));gap:10px}.tc-health-card{padding:13px;border:1px solid var(--line);border-radius:10px;background:var(--surface2)}.tc-health-card .big{font-size:17px;font-weight:760}
.tc-paths{display:flex;gap:6px;flex-wrap:wrap}.tc-path{display:inline-flex;align-items:center;gap:6px;padding:4px 8px;border-radius:7px;border:1px solid var(--line);font-size:11px;font-weight:700}
.tc-path.ok{color:var(--ok)}.tc-path.bad{color:var(--danger)}
.tc-log{display:grid;grid-template-columns:135px 78px 110px minmax(220px,1fr);gap:10px;align-items:start;padding:9px 11px;border-bottom:1px solid var(--line)}

.tc-table-wrap{position:relative}.tc-table-tools{display:flex;gap:7px;align-items:center;flex-wrap:wrap;padding:8px 10px;border-bottom:1px solid var(--line);background:var(--surface2);border-radius:11px 11px 0 0;position:relative;z-index:4}
.tc-table-tools .tc-local-search{flex:1;min-width:220px}.tc-table-tools .tc-advanced{display:none;gap:7px;align-items:center;flex-wrap:wrap;width:100%;padding-top:8px;border-top:1px solid var(--line)}.tc-table-tools.filter-open .tc-advanced{display:flex}
.tc-filter-column,.tc-filter-op{max-width:220px}.tc-filter-value{min-width:150px;flex:0 1 240px}.tc-count{font-size:11px;color:var(--muted);white-space:nowrap;margin-left:auto}
.tc-colbox{position:relative}.tc-colmenu{display:none;position:absolute;right:0;top:calc(100% + 5px);z-index:100;width:230px;max-height:350px;overflow:auto;background:var(--surface);border:1px solid var(--line);border-radius:9px;padding:8px;box-shadow:var(--shadow)}.tc-colbox.open .tc-colmenu{display:block}.tc-colmenu label{display:flex;gap:8px;align-items:center;padding:6px}
.tc-scroll{overflow:auto;max-width:100%;border-radius:0 0 11px 11px}table{width:100%;border-collapse:collapse;min-width:760px}th,td{padding:10px 12px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:10px;text-transform:uppercase;letter-spacing:.045em;color:var(--muted);background:var(--surface2);position:sticky;top:0;z-index:2;cursor:pointer;white-space:nowrap}th[data-sort]::after{content:" ↕";opacity:.3}
tbody tr:hover{background:var(--surface2)}

.tc-copy-btn{margin-left:5px;padding:3px 6px;font-size:10px}.tc-copy-ok{border-color:var(--accent)!important;color:var(--accent)!important}
.tc-toast{border-left:3px solid var(--accent)}.tc-toast.bad{border-left-color:var(--danger)}
.tc-diff-line{padding:3px 9px;white-space:pre-wrap;word-break:break-word;border-bottom:1px solid color-mix(in srgb,var(--line) 45%,transparent)}.tc-diff-line.ok{background:color-mix(in srgb,var(--ok) 9%,transparent);color:var(--ok)}.tc-diff-line.bad{background:color-mix(in srgb,var(--danger) 9%,transparent);color:var(--danger)}.tc-diff-line.warn{background:color-mix(in srgb,var(--warn) 9%,transparent);color:var(--warn)}

.tc-palette{display:none;position:fixed;inset:0;background:rgba(0,0,0,.54);z-index:200;padding:9vh 18px}.tc-palette.open{display:block}.tc-palette-card{width:min(720px,100%);max-height:78vh;margin:auto;background:var(--surface);border:1px solid var(--line);border-radius:14px;box-shadow:0 24px 70px rgba(0,0,0,.38);overflow:hidden}.tc-palette-search{padding:13px;border-bottom:1px solid var(--line)}.tc-palette-search input{width:100%;font-size:15px}.tc-palette-list{max-height:60vh;overflow:auto;padding:7px}.tc-palette-group{padding:8px 10px 5px;color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:.1em;font-weight:800}.tc-palette-item{display:flex;justify-content:space-between;gap:15px;padding:9px 10px;border-radius:8px;color:var(--text)}.tc-palette-item:hover,.tc-palette-item.active{background:var(--accent-soft)}.tc-palette-item span:last-child{color:var(--muted);font-size:11px}

.tc-router-primary{display:flex;gap:7px;flex-wrap:wrap;margin-top:12px}.tc-router-toolbox{margin-top:10px}.tc-router-toolbox summary{cursor:pointer;color:var(--accent);font-weight:700}.tc-router-tool-groups{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:10px;margin-top:10px}.tc-router-tool-group{border:1px solid var(--line);background:var(--surface2);border-radius:9px;padding:9px}.tc-router-tool-group strong{display:block;margin-bottom:5px}.tc-router-tool-group a{display:block;padding:5px 3px;color:var(--muted)}.tc-router-tool-group a:hover{color:var(--text)}
.tc-workspace-tabs{display:flex;gap:5px;overflow:auto;margin:2px 0 12px;padding-bottom:2px}.tc-workspace-tabs button{white-space:nowrap}.tc-workspace-tabs button.active{background:var(--accent-soft);border-color:color-mix(in srgb,var(--accent) 35%,var(--line));color:var(--text)}
.tc-workspace-section{display:none}.tc-workspace-section.active{display:block}

.login{max-width:430px;margin:8vh auto}.login .panel{box-shadow:var(--shadow)}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px}.dot.online{background:var(--ok)}.dot.offline{background:var(--danger)}

@media(max-width:1050px){
 :root{--sidebar:220px}.tc-command-btn{min-width:150px}.tc-content{padding:18px}
}
@media(max-width:820px){
 .tc-shell{display:block}.tc-sidebar{position:fixed;left:-280px;top:0;width:260px;transition:left .18s ease;box-shadow:var(--shadow)}body.tc-nav-open .tc-sidebar{left:0}.tc-menu-btn{display:inline-block}
 .tc-topbar{padding:0 12px;height:58px}.tc-command-btn{min-width:0;width:42px}.tc-command-btn .tc-command-label,.tc-command-btn .tc-kbd{display:none}
 .tc-content{padding:14px 10px 40px}.tc-page-tools{flex-wrap:wrap}.tc-page-tools input{max-width:none;width:100%}.cards{grid-template-columns:1fr}
 .tc-account>button span{display:none}.tc-logo{width:178px}.tc-table-tools .tc-local-search{min-width:100%}.tc-count{margin-left:0}
 table{min-width:680px}.tc-log{grid-template-columns:1fr}.tc-router-primary{display:grid;grid-template-columns:1fr 1fr}.tc-router-primary a button{width:100%}
}
@media(prefers-reduced-motion:reduce){*{scroll-behavior:auto!important;transition:none!important}}
'''

JS = r'''
(function(){
 const root=document.documentElement;
 const saved=localStorage.getItem('tikcentral:theme');
 root.dataset.theme=saved||(matchMedia('(prefers-color-scheme: light)').matches?'light':'dark');

 function themeLabel(){const b=document.getElementById('tcTheme');if(b)b.textContent=root.dataset.theme==='light'?'Dark':'Light'}
 window.tcToggleTheme=function(){root.dataset.theme=root.dataset.theme==='light'?'dark':'light';localStorage.setItem('tikcentral:theme',root.dataset.theme);themeLabel()};

 async function tcWriteClipboard(text){
   text=String(text??'');
   try{if(navigator.clipboard&&window.isSecureContext){await navigator.clipboard.writeText(text);return true}}catch(_){}
   try{const ta=document.createElement('textarea');ta.value=text;ta.setAttribute('readonly','');ta.style.position='fixed';ta.style.opacity='0';document.body.appendChild(ta);ta.select();ta.setSelectionRange(0,ta.value.length);const ok=document.execCommand('copy');ta.remove();return !!ok}catch(_){return false}
 }
 window.tcCopy=async function(valueOrElement,button){
   let text='';
   if(valueOrElement&&typeof valueOrElement==='object')text=('value' in valueOrElement)?valueOrElement.value:(valueOrElement.innerText||valueOrElement.textContent||'');
   else text=String(valueOrElement??'');
   const ok=await tcWriteClipboard(text);
   if(button){const old=button.textContent;button.textContent=ok?'Copied':'Failed';button.classList.toggle('tc-copy-ok',ok);setTimeout(()=>{button.textContent=old;button.classList.remove('tc-copy-ok')},1100)}
   return ok;
 };
 function installCopyButtons(rootNode=document){
   const rootEl=(rootNode&&rootNode.querySelectorAll)?rootNode:document;
   const fields=[...rootEl.querySelectorAll('input,textarea,select')];
   if(rootNode&&rootNode.matches&&rootNode.matches('input,textarea,select'))fields.unshift(rootNode);
   fields.forEach(el=>{
     const type=(el.getAttribute('type')||'text').toLowerCase();
     if(['hidden','checkbox','radio','submit','button','file','password'].includes(type)||el.dataset.noCopy||['tcGlobalSearch','tcPaletteSearch'].includes(el.id)||el.dataset.tcCopyReady)return;
     el.dataset.tcCopyReady='1';const b=document.createElement('button');b.type='button';b.className='tc-copy-btn';b.textContent='Copy';b.title='Copy field value';
     b.onclick=e=>{e.preventDefault();e.stopPropagation();window.tcCopy(el,b)};el.insertAdjacentElement('afterend',b);
   });
   const copyables=[...rootEl.querySelectorAll('[data-copy],code.tc-copy,pre.tc-copy')];
   copyables.forEach(el=>{if(el.dataset.tcCopyReady)return;el.dataset.tcCopyReady='1';const b=document.createElement('button');b.type='button';b.className='tc-copy-btn';b.textContent='Copy';b.onclick=e=>{e.preventDefault();e.stopPropagation();window.tcCopy(el,b)};el.insertAdjacentElement('afterend',b)});
 }
 document.addEventListener('click',e=>{const b=e.target.closest('[data-copy-target]');if(!b)return;const t=document.querySelector(b.dataset.copyTarget);if(t)window.tcCopy(t,b)});

 function numeric(s){const v=Number(String(s).replace(/[^0-9+-.]/g,''));return Number.isFinite(v)?v:null}
 function sortTable(table,idx,dir){const tb=table.tBodies[0];if(!tb)return;const rows=[...tb.rows];rows.sort((a,b)=>{let x=(a.cells[idx]?.innerText||'').trim(),y=(b.cells[idx]?.innerText||'').trim();const nx=numeric(x),ny=numeric(y);let cmp=(nx!==null&&ny!==null)?nx-ny:x.localeCompare(y,undefined,{numeric:true,sensitivity:'base'});return dir*cmp});rows.forEach(row=>tb.appendChild(row))}
 function comparable(v){const s=String(v??'').trim();const d=Date.parse(s);if(s&&Number.isFinite(d)&&(/\d{4}-\d{1,2}-\d{1,2}/.test(s)||s.includes('T')))return {type:'date',value:d};const n=numeric(s);if(s&&n!==null)return {type:'number',value:n};return {type:'text',value:s.toLowerCase()}}
 function matchOperator(cell,op,wanted){const raw=String(cell??'').trim();if(op==='contains')return raw.toLowerCase().includes(String(wanted??'').toLowerCase());if(op==='!contains')return !raw.toLowerCase().includes(String(wanted??'').toLowerCase());const a=comparable(raw),b=comparable(wanted);let av=a.value,bv=b.value;if(a.type!==b.type){av=raw.toLowerCase();bv=String(wanted??'').toLowerCase()}return op==='='?av===bv:op==='!='?av!==bv:op==='>'?av>bv:op==='>='?av>=bv:op==='<'?av<bv:op==='<='?av<=bv:true}
 function filterTable(wrap){const q=(wrap.querySelector('.tc-local-search')?.value||'').toLowerCase();const col=Number(wrap.querySelector('.tc-filter-column')?.value??-1);const op=wrap.querySelector('.tc-filter-op')?.value||'contains';const wanted=wrap.querySelector('.tc-filter-value')?.value||'';let shown=0,total=0;wrap.querySelectorAll('tbody tr').forEach(r=>{total++;const textOk=!q||(r.innerText||'').toLowerCase().includes(q);const filterOk=!wanted||col<0||matchOperator(r.cells[col]?.innerText||'',op,wanted);const ok=textOk&&filterOk;r.style.display=ok?'':'none';if(ok)shown++});const count=wrap.querySelector('.tc-count');if(count)count.textContent=shown+' / '+total}
 function enhanceTable(table,index){
   if(table.dataset.tcReady)return;table.dataset.tcReady='1';
   const panel=table.parentElement,wrap=document.createElement('div');wrap.className='tc-table-wrap';panel.insertBefore(wrap,table);
   const tools=document.createElement('div');tools.className='tc-table-tools';
   tools.innerHTML='<input class="tc-local-search" data-no-copy placeholder="Search rows…"><button type="button" class="tc-filter-toggle">Filter</button><span class="tc-count"></span><div class="tc-colbox"><button type="button" class="tc-colbtn">Columns</button><div class="tc-colmenu"></div></div><button type="button" class="tc-reset">Reset</button><div class="tc-advanced"><select class="tc-filter-column" data-no-copy></select><select class="tc-filter-op" data-no-copy><option value="contains">contains</option><option value="!contains">does not contain</option><option value="=">=</option><option value="!=">!=</option><option value=">">&gt;</option><option value=">=">&gt;=</option><option value="<">&lt;</option><option value="<=">&lt;=</option></select><input class="tc-filter-value" data-no-copy placeholder="Filter value…"></div>';
   wrap.appendChild(tools);const scroll=document.createElement('div');scroll.className='tc-scroll';wrap.appendChild(scroll);scroll.appendChild(table);
   const key='tikcentral:columns:'+location.pathname+':'+index;let hidden=[];const stored=localStorage.getItem(key);try{hidden=stored!==null?JSON.parse(stored):(table.dataset.defaultHidden||'').split(',').map(x=>Number(x.trim())).filter(Number.isFinite)}catch(_){hidden=[]}
   const headers=[...table.querySelectorAll('thead th')],menu=tools.querySelector('.tc-colmenu'),filterColumn=tools.querySelector('.tc-filter-column');
   headers.forEach((th,i)=>{th.dataset.sort='1';let dir=1;th.onclick=e=>{if(e.target.closest('input,button,select'))return;sortTable(table,i,dir);dir*=-1};const label=(th.innerText||('Column '+(i+1))).trim()||('Column '+(i+1));const opt=document.createElement('option');opt.value=String(i);opt.textContent=label;filterColumn.appendChild(opt);const row=document.createElement('label');row.innerHTML='<input type="checkbox" '+(hidden.includes(i)?'':'checked')+'><span></span>';row.querySelector('span').textContent=label;const cb=row.querySelector('input');cb.onchange=()=>setCol(i,cb.checked);menu.appendChild(row);setCol(i,!hidden.includes(i),false)});
   function setCol(i,show,save=true){[...table.rows].forEach(r=>{if(r.cells[i])r.cells[i].style.display=show?'':'none'});hidden=hidden.filter(x=>x!==i);if(!show)hidden.push(i);if(save)localStorage.setItem(key,JSON.stringify(hidden))}
   tools.querySelector('.tc-filter-toggle').onclick=()=>tools.classList.toggle('filter-open');
   tools.querySelector('.tc-colbtn').onclick=e=>{e.stopPropagation();tools.querySelector('.tc-colbox').classList.toggle('open')};
   ['input','change'].forEach(ev=>{tools.querySelector('.tc-local-search').addEventListener(ev,()=>filterTable(wrap));tools.querySelector('.tc-filter-value').addEventListener(ev,()=>filterTable(wrap))});
   filterColumn.onchange=()=>filterTable(wrap);tools.querySelector('.tc-filter-op').onchange=()=>filterTable(wrap);
   tools.querySelector('.tc-reset').onclick=()=>{tools.querySelector('.tc-local-search').value='';tools.querySelector('.tc-filter-value').value='';tools.querySelector('.tc-filter-op').value='contains';hidden=[];localStorage.removeItem(key);headers.forEach((_,i)=>setCol(i,true,false));menu.querySelectorAll('input').forEach(x=>x.checked=true);filterTable(wrap)};
   filterTable(wrap);
 }

 function globalFilter(){const q=(document.getElementById('tcGlobalSearch')?.value||'').toLowerCase();const sections=[...document.querySelectorAll('.tc-workspace-section')];if(sections.length){if(q)sections.forEach(s=>s.classList.add('active'));else{sections.forEach(s=>s.classList.remove('active'));const active=document.querySelector('.tc-workspace-tabs button.active');const name=active?.textContent;if(name)document.querySelector('.tc-workspace-section[data-tab="'+CSS.escape(name)+'"]')?.classList.add('active')}}document.querySelectorAll('.tc-content .panel,.tc-content .card').forEach(el=>{if(el.querySelector('.tc-table-wrap'))return;el.style.display=!q||(el.innerText||'').toLowerCase().includes(q)?'':'none'});document.querySelectorAll('.tc-table-wrap').forEach(w=>{const inp=w.querySelector('.tc-local-search');if(inp){inp.value=q;filterTable(w)}})}

 function openPalette(){const p=document.getElementById('tcPalette');if(!p)return;p.classList.add('open');const i=document.getElementById('tcPaletteSearch');if(i){i.value='';filterPalette();setTimeout(()=>i.focus(),0)}}
 function closePalette(){document.getElementById('tcPalette')?.classList.remove('open')}
 function filterPalette(){const q=(document.getElementById('tcPaletteSearch')?.value||'').trim().toLowerCase();document.querySelectorAll('.tc-palette-item').forEach(x=>x.style.display=!q||(x.dataset.search||'').includes(q)?'flex':'none')}

 const toolCategory=(href)=>{
   if(/timeline|incidents|diagnostics|network-quality|wan-probe|interfaces|lte|mtu|time-health|traffic|capacity/.test(href))return 'Troubleshoot';
   if(/desired-state|compliance|security-audit|protection|audit|automation-inventory|log-patterns|topology/.test(href))return 'Configuration & security';
   if(/site|notes|customer-report|maintenance-history|hardware|lifecycle|certificates/.test(href))return 'Site & assets';
   if(/recovery|replacements|rescue|change|commissioning|public-ip|local-utilization/.test(href))return 'Lifecycle & recovery';
   return 'Other tools';
 };
 function organizeRouterWorkspace(){
   if(!/^\/operations\/\d+\/?$/.test(location.pathname))return;
   const content=document.querySelector('.tc-content');if(!content)return;
   const panels=[...content.children].filter(x=>x.classList?.contains('panel'));
   if(!panels.length)return;
   const hero=panels[0],actions=hero.querySelector('.inline');
   if(actions){
     const links=[...actions.querySelectorAll(':scope > a')];
     const primaryPatterns=[/\/timeline\/\d+\/?$/,/\/incidents\//,/\/network-quality\//,/\/site\//,/\/notes\//];
     const primary=[];const rest=[];
     links.forEach(a=>(primaryPatterns.some(rx=>rx.test(a.getAttribute('href')||''))&&primary.length<5?primary:rest).push(a));
     actions.className='tc-router-primary';actions.innerHTML='';primary.forEach(a=>actions.appendChild(a));
     const routerId=location.pathname.split('/').filter(Boolean).pop();const ai=document.createElement('a');ai.href='/ai/'+routerId;ai.innerHTML='<button class="primary">AI analysis</button>';actions.appendChild(ai);
     if(rest.length){
       const details=document.createElement('details');details.className='tc-router-toolbox';details.innerHTML='<summary>All router tools ('+rest.length+')</summary><div class="tc-router-tool-groups"></div>';
       const groups={};rest.forEach(a=>{const g=toolCategory(a.getAttribute('href')||'');(groups[g]||(groups[g]=[])).push(a)});
       const box=details.querySelector('.tc-router-tool-groups');Object.entries(groups).forEach(([name,items])=>{const d=document.createElement('div');d.className='tc-router-tool-group';d.innerHTML='<strong>'+name+'</strong>';items.forEach(a=>{const copy=a.cloneNode(true);const btn=copy.querySelector('button');if(btn){const label=btn.textContent;copy.textContent=label}d.appendChild(copy)});box.appendChild(d)});hero.appendChild(details);
     }
   }
   const categoryMap={
     'Summary':['Lifecycle','Site / customer','Outage domain','Access / commissioning','Telemetry'],
     'Connectivity':['Interface health','Traffic','Capacity trends','WAN probe','Network quality','Time / NTP','MTU / MSS','Public IP churn','Local network utilization','LTE','Topology'],
     'Configuration':['Security exposure','RouterOS automation','Desired state','Commissioning checklist','Golden policy','Router log patterns','Performance','RouterOS / RouterBOOT'],
     'Assets':['Model capabilities','Hardware lifecycle'],
   };
   const leftovers=[];const sections={};
   Object.keys(categoryMap).forEach(name=>{const s=document.createElement('div');s.className='tc-workspace-section';s.dataset.tab=name;sections[name]=s});
   [...content.children].forEach(el=>{
     if(el===hero||el.classList?.contains('tc-page-tools'))return;
     const h=el.querySelector?.(':scope > h3');const title=h?.textContent?.trim()||'';
     let dest='';for(const [name,titles] of Object.entries(categoryMap)){if(titles.includes(title)){dest=name;break}}
     if(dest)sections[dest].appendChild(el);else leftovers.push(el);
   });
   const activity=document.createElement('div');activity.className='tc-workspace-section';activity.dataset.tab='Activity';leftovers.forEach(el=>activity.appendChild(el));sections.Activity=activity;
   const tabs=document.createElement('div');tabs.className='tc-workspace-tabs';
   Object.keys(sections).forEach((name,i)=>{const b=document.createElement('button');b.type='button';b.textContent=name;b.className=i===0?'active':'';b.onclick=()=>{tabs.querySelectorAll('button').forEach(x=>x.classList.remove('active'));b.classList.add('active');Object.values(sections).forEach(s=>s.classList.remove('active'));sections[name].classList.add('active');localStorage.setItem('tikcentral:router-tab',name)};tabs.appendChild(b)});
   hero.insertAdjacentElement('afterend',tabs);Object.values(sections).forEach(s=>content.appendChild(s));
   const saved=localStorage.getItem('tikcentral:router-tab');const target=sections[saved]?saved:Object.keys(sections)[0];[...tabs.children].find(b=>b.textContent===target)?.click();
 }

 function decorateStatuses(){document.querySelectorAll('td').forEach(td=>{if(td.children.length)return;const s=(td.innerText||'').trim().toLowerCase();let tone='';if(['healthy','online','passed','success','succeeded','enabled','ready','commissioned','matches baseline','ok','up'].includes(s))tone='ok';else if(['warning','partial','degraded','pending','queued','running','verifying','drift','drift detected','saturated'].includes(s))tone='warn';else if(['failed','error','critical','offline','down'].includes(s))tone='bad';if(tone){const text=td.innerText;td.innerHTML='<span class="tc-status '+tone+'"><span class="tc-status-dot"></span><span></span></span>';td.firstChild.lastChild.textContent=text}})}

 document.addEventListener('click',e=>{
   if(!e.target.closest('.tc-colbox'))document.querySelectorAll('.tc-colbox.open').forEach(x=>x.classList.remove('open'));
   if(!e.target.closest('.tc-account'))document.querySelector('.tc-account')?.classList.remove('open');
   if(e.target.id==='tcPalette')closePalette();
 });
 document.addEventListener('keydown',e=>{
   if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==='k'){e.preventDefault();openPalette()}
   if(e.key==='Escape'){closePalette();document.body.classList.remove('tc-nav-open')}
 });
 document.addEventListener('DOMContentLoaded',()=>{
   themeLabel();installCopyButtons();organizeRouterWorkspace();decorateStatuses();
   const observer=new MutationObserver(ms=>ms.forEach(m=>m.addedNodes.forEach(node=>{if(node.nodeType===1)installCopyButtons(node)})));observer.observe(document.body,{childList:true,subtree:true});
   document.querySelectorAll('table').forEach(enhanceTable);
   const g=document.getElementById('tcGlobalSearch');if(g)g.oninput=globalFilter;
   const clear=document.getElementById('tcPageSearchClear');if(clear)clear.onclick=()=>{if(g){g.value='';globalFilter()}};
   document.getElementById('tcCommandBtn')?.addEventListener('click',openPalette);
   document.getElementById('tcPaletteSearch')?.addEventListener('input',filterPalette);
   document.getElementById('tcMenuBtn')?.addEventListener('click',()=>document.body.classList.toggle('tc-nav-open'));
   document.getElementById('tcAccountBtn')?.addEventListener('click',e=>{e.stopPropagation();document.querySelector('.tc-account')?.classList.toggle('open')});
 });
})();
'''


def page(title: str, body: str, user=None, active: str = "") -> HTMLResponse:
    active = active or _infer_active(title)
    light = settings.ASSETS["logo_light"]
    dark = settings.ASSETS["logo_dark"]
    icon = settings.ASSETS["icon"]
    localized = localize_html_iso_timestamps(body or "").replace(" UTC", " Montréal")
    if not user:
        html_doc = f'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{html.escape(title)} - Tikcentral</title><link rel="icon" href="{icon}"><script>(function(){{try{{document.documentElement.dataset.theme=localStorage.getItem('tikcentral:theme')||(matchMedia('(prefers-color-scheme: light)').matches?'light':'dark')}}catch(e){{document.documentElement.dataset.theme='dark'}}}})();</script><style>{CSS}</style></head><body><main class="tc-content" style="max-width:520px;margin:auto;padding-top:7vh"><div class="tc-brand" style="justify-content:center;border:0"><img class="tc-logo tc-logo-light" src="{light}" alt="Opticable"><img class="tc-logo tc-logo-dark" src="{dark}" alt="Opticable"></div>{localized}</main><script>{JS}</script></body></html>'''
        return HTMLResponse(html_doc)
    sidebar = ""
    account = ""
    palette_items = ""
    category = NAV_CATEGORY.get(active, "Workspace")
    if user:
        try:
            email = user["email"]
            role = user["role"] if user["role"] in {"viewer", "technician", "admin"} else "viewer"
        except Exception:
            email, role = "admin", "admin"
        groups = []
        palette = []
        for group, items in NAV_GROUPS:
            links = []
            for key, href, label in items:
                if role != "admin" and key in {"users", "settings", "ssh"}:
                    continue
                cls = "active" if key == active else ""
                links.append(f'<a class="{cls}" href="{href}">{html.escape(label)}</a>')
                palette.append(f'<a class="tc-palette-item" href="{href}" data-search="{html.escape((group+" "+label).lower())}"><span>{html.escape(label)}</span><span>{html.escape(group)}</span></a>')
            if links:
                opened = " open" if group in {"Overview", category} else ""
                groups.append(f'<details class="tc-nav-group"{opened}><summary class="tc-nav-label">{html.escape(group)}</summary><nav class="tc-nav">{"".join(links)}</nav></details>')
        sidebar = "".join(groups)
        palette_items = "".join(palette)
        account = f'''<div class="tc-account"><button type="button" id="tcAccountBtn"><span>{html.escape(email)}</span> ▾</button><div class="tc-account-menu"><div style="padding:8px 10px"><strong>{html.escape(email)}</strong><div class="muted">{html.escape(role.title())}</div></div><a href="/account/password"><button type="button">Account & password</button></a><form method="post" action="/logout"><button>Sign out</button></form></div></div>'''
    page_tools = '<div class="tc-page-tools"><input id="tcGlobalSearch" data-no-copy placeholder="Search within this page…"><button type="button" id="tcPageSearchClear">Clear</button><span class="hint">Use Ctrl/⌘ K for navigation</span></div>' if user else ''
    shell = f'''<div class="tc-shell">
<aside class="tc-sidebar" id="tcSidebar"><div class="tc-brand"><a href="/"><img class="tc-logo tc-logo-light" src="{light}" alt="Opticable"><img class="tc-logo tc-logo-dark" src="{dark}" alt="Opticable"><img class="tc-icon" src="{icon}" alt="Opticable"></a></div>{sidebar}<div class="tc-sidebar-foot">Tikcentral · Opticable<br>Management plane</div></aside>
<div class="tc-main"><header class="tc-topbar"><button class="tc-menu-btn" id="tcMenuBtn" type="button">☰</button><div class="tc-page-meta"><div class="tc-page-title">{html.escape(title)}</div><div class="tc-breadcrumb">{html.escape(category)}</div></div>
<div class="tc-top-actions">{f'<button class="tc-command-btn" id="tcCommandBtn" type="button"><span class="tc-command-label">Go to…</span><span class="tc-kbd">Ctrl K</span></button><button id="tcTheme" type="button" onclick="tcToggleTheme()">Theme</button>{account}' if user else ''}</div></header>
<main class="tc-content">{page_tools}{localized}</main></div></div>'''
    palette = f'''<div class="tc-palette" id="tcPalette"><div class="tc-palette-card"><div class="tc-palette-search"><input id="tcPaletteSearch" data-no-copy placeholder="Go to a feature…"></div><div class="tc-palette-list">{palette_items}</div></div></div>''' if user else ""
    html_doc = f'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{html.escape(title)} - Tikcentral</title><link rel="icon" href="{icon}"><script>(function(){{try{{document.documentElement.dataset.theme=localStorage.getItem('tikcentral:theme')||(matchMedia('(prefers-color-scheme: light)').matches?'light':'dark')}}catch(e){{document.documentElement.dataset.theme='dark'}}}})();</script><style>{CSS}</style></head><body>{shell}{palette}<script>{JS}</script></body></html>'''
    return HTMLResponse(html_doc)
