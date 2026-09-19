"""Single HTML renderer for all Tikcentral pages."""

import html

from fastapi.responses import HTMLResponse

from app import settings
from app.ui_time import localize_html_iso_timestamps

NAV = [
    ("dashboard", "/", "Dashboard"),
    ("routers", "/routers", "Routers"),
    ("enroll", "/enroll", "Enroll"),
    ("guardian", "/guardian", "Guardian"),
    ("reliability", "/reliability", "Reliability"),
    ("operations", "/operations", "Operations"),
    ("customers", "/customers", "Customers"),
    ("alerts", "/alerts", "Alerts"),
    ("replacements", "/replacements", "Replacements"),
    ("maintenance-automation", "/maintenance-automation", "Post-change"),
    ("lifecycle", "/lifecycle", "Lifecycle"),
    ("upgrade-campaigns", "/upgrade-campaigns", "Upgrades"),
    ("compliance", "/compliance", "Compliance"),
    ("rescue", "/rescue", "Rescue"),
    ("automation", "/automation", "Automation"),
    ("ssh", "/ssh", "SSH"),
    ("changes", "/changes", "Changes"),
    ("change-calendar", "/change-calendar", "Calendar"),
    ("fleet-search", "/fleet-search", "Fleet Search"),
    ("model-capabilities", "/model-capabilities", "Models"),
    ("hardware-lifecycle", "/hardware-lifecycle", "Hardware Life"),
    ("identity-collisions", "/identity-collisions", "Identity"),
    ("config-search", "/config-search", "Config Search"),
    ("retention", "/retention", "Retention"),
    ("audit", "/audit", "Audit"),
    ("operator-audit", "/operator-audit", "Operator Audit"),
    ("system-health", "/system-health", "System"),
    ("database-health", "/database-health", "DB Health"),
    ("users", "/admin/users", "Users"),
    ("settings", "/settings", "Settings"),
]


def _infer_active(title: str) -> str:
    t = (title or "").lower()
    for key, _, label in NAV:
        if label.lower() in t:
            return key
    if "password" in t:
        return "settings"
    return "dashboard" if t == "dashboard" else ""


CSS = r'''
:root{--bg:#0c120f;--bg2:#101713;--panel:#151d19;--panel2:#1b2520;--line:#2b3931;--text:#f1f5f2;--muted:#9aa8a0;--green:#58cf8a;--green2:#278f5d;--green3:#146b49;--danger:#e66c7c;--warn:#d9a743;--input:#111914;--shadow:0 8px 24px rgba(0,0,0,.16)}
html[data-theme="light"]{--bg:#f4f7f5;--bg2:#eef4f0;--panel:#fff;--panel2:#f3f7f4;--line:#d9e2dc;--text:#202722;--muted:#6b786f;--green:#278f5d;--green2:#208354;--green3:#146b49;--danger:#bd4154;--warn:#976410;--input:#fff;--shadow:0 7px 22px rgba(32,68,48,.08)}
*{box-sizing:border-box}html,body{margin:0;min-height:100%;background:var(--bg);color:var(--text);font:14px/1.45 system-ui,-apple-system,Segoe UI,sans-serif}body{background:linear-gradient(180deg,var(--bg2),var(--bg) 260px)}a{color:var(--green);text-decoration:none}a:hover{text-decoration:none;color:color-mix(in srgb,var(--green) 80%,white)}button,input,select,textarea{font:inherit}button{border:1px solid var(--line);background:var(--panel2);color:var(--text);border-radius:8px;padding:8px 12px;cursor:pointer}button:hover:not(:disabled){border-color:color-mix(in srgb,var(--green) 35%,var(--line));background:color-mix(in srgb,var(--green) 7%,var(--panel2))}button:disabled{opacity:.5;cursor:not-allowed}.primary{background:var(--green2)!important;border-color:var(--green3)!important;color:#fff!important}.primary:hover{background:#2aa167!important}.danger{background:color-mix(in srgb,var(--danger) 15%,var(--panel2))!important;border-color:color-mix(in srgb,var(--danger) 50%,var(--line))!important;color:var(--danger)!important}input,select,textarea{background:var(--input);color:var(--text);border:1px solid var(--line);border-radius:8px;padding:9px 10px}input:focus,select:focus,textarea:focus{outline:none;border-color:var(--green);box-shadow:0 0 0 3px color-mix(in srgb,var(--green) 15%,transparent)}textarea.script{width:100%;min-height:60vh;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}code{background:color-mix(in srgb,var(--green) 5%,var(--panel2));padding:2px 5px;border-radius:5px}.muted,.sub{color:var(--muted)}.inline{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.error{background:color-mix(in srgb,var(--danger) 12%,var(--panel));border:1px solid color-mix(in srgb,var(--danger) 45%,var(--line));padding:10px;border-radius:9px}.badge,.tc-status{display:inline-flex;align-items:center;gap:6px;padding:4px 9px;border-radius:999px;font-size:11px;font-weight:750;border:1px solid var(--line);white-space:nowrap}.tc-status.ok{color:#50d78c;background:color-mix(in srgb,#35c979 12%,transparent);border-color:color-mix(in srgb,#35c979 40%,var(--line))}.tc-status.warn{color:#edba59;background:color-mix(in srgb,#e4aa39 12%,transparent);border-color:color-mix(in srgb,#e4aa39 42%,var(--line))}.tc-status.bad{color:#ef7b89;background:color-mix(in srgb,#e95f73 12%,transparent);border-color:color-mix(in srgb,#e95f73 42%,var(--line))}
.tc-status-dot{width:8px;height:8px;border-radius:50%;background:currentColor;box-shadow:0 0 0 0 currentColor;display:inline-block}.tc-status.live .tc-status-dot{animation:tcPulse 1.8s ease-out infinite}.tc-status.warn.live .tc-status-dot{animation-duration:1.25s}.tc-status.bad.live .tc-status-dot{animation-duration:.9s}@keyframes tcPulse{0%{box-shadow:0 0 0 0 color-mix(in srgb,currentColor 45%,transparent)}70%{box-shadow:0 0 0 7px transparent}100%{box-shadow:0 0 0 0 transparent}}
.tc-health-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(165px,1fr));gap:12px}.tc-health-card{position:relative;padding:14px 15px;border:1px solid var(--line);border-radius:12px;background:var(--panel2);overflow:hidden}.tc-health-card:before{content:"";position:absolute;left:0;top:0;bottom:0;width:4px;background:var(--muted)}.tc-health-card.ok:before{background:var(--green)}.tc-health-card.warn:before{background:var(--warn)}.tc-health-card.bad:before{background:var(--danger)}.tc-health-card .big{font-size:18px;font-weight:800;margin-bottom:3px}.tc-paths{display:flex;gap:7px;flex-wrap:wrap}.tc-path{display:inline-flex;align-items:center;gap:6px;padding:5px 8px;border-radius:8px;border:1px solid var(--line);font-size:12px;font-weight:700}.tc-path.ok{color:#50d78c;background:color-mix(in srgb,#35c979 9%,transparent)}.tc-path.bad{color:#ef7b89;background:color-mix(in srgb,#e95f73 9%,transparent)}.tc-log{display:grid;grid-template-columns:150px 90px 120px minmax(220px,1fr);gap:10px;align-items:start;padding:10px 12px;border-bottom:1px solid var(--line)}.tc-log:last-child{border-bottom:0}.tc-log:hover{background:color-mix(in srgb,var(--green) 5%,transparent)}.tc-log .sev{font-weight:800;text-transform:uppercase;font-size:11px}.tc-log.info .sev{color:var(--green)}.tc-log.warning .sev{color:var(--warn)}.tc-log.critical .sev{color:var(--danger)}.tc-toast{animation:tcSlideIn .24s ease-out both;border-left:4px solid var(--green)}.tc-copy-btn{margin-left:6px;padding:4px 7px;font-size:11px;vertical-align:middle}.tc-copy-ok{border-color:var(--green)!important;color:var(--green)!important}.tc-toast.bad{border-left-color:var(--danger)}.tc-diff-line{padding:3px 10px;white-space:pre-wrap;word-break:break-word;border-bottom:1px solid color-mix(in srgb,var(--line) 45%,transparent)}.tc-diff-line.ok{background:color-mix(in srgb,var(--green) 10%,transparent);color:#70df9f}.tc-diff-line.bad{background:color-mix(in srgb,var(--danger) 10%,transparent);color:#f08a98}.tc-diff-line.warn{background:color-mix(in srgb,var(--warn) 10%,transparent);color:#edba59}.tc-diff-line.muted{color:var(--muted);background:var(--panel2)}@keyframes tcSlideIn{from{opacity:0;transform:translateY(-7px)}to{opacity:1;transform:none}}@media(prefers-reduced-motion:reduce){.tc-status.live .tc-status-dot,.tc-toast{animation:none}}
.tc-app{max-width:1860px;margin:auto;padding:14px 22px 48px}.tc-head{display:grid;grid-template-columns:220px minmax(500px,1fr) auto;gap:14px;align-items:center;padding:10px 13px;margin-bottom:14px;background:var(--panel);border:1px solid var(--line);border-radius:15px;box-shadow:var(--shadow);overflow:visible}.tc-brand{width:210px;min-width:210px;overflow:visible}.tc-brand a{display:block;width:210px;overflow:visible}.tc-logo{display:block;width:200px!important;height:auto!important;max-width:none!important;max-height:none!important}.tc-logo-light{display:none}.tc-logo-dark{display:block}html[data-theme="light"] .tc-logo-dark{display:none}html[data-theme="light"] .tc-logo-light{display:block}.tc-icon{display:none;width:46px;height:46px;object-fit:contain}.tc-nav{display:flex;gap:4px;align-items:center;flex-wrap:wrap;padding:4px;background:var(--panel2);border-radius:10px}.tc-nav a{color:var(--muted);font-weight:650;padding:8px 10px;border-radius:7px;white-space:nowrap}.tc-nav a:hover{color:var(--text);background:color-mix(in srgb,var(--green) 7%,var(--panel2))}.tc-nav a.active{color:var(--text);background:color-mix(in srgb,var(--green) 15%,var(--panel2));box-shadow:inset 0 0 0 1px color-mix(in srgb,var(--green) 25%,var(--line))}.tc-account{display:flex;gap:8px;align-items:center;background:var(--panel2);border:1px solid var(--line);border-radius:10px;padding:6px 7px 6px 10px}.tc-account span{max-width:210px;overflow:hidden;text-overflow:ellipsis}.tc-tools{display:flex;gap:9px;align-items:center;margin-bottom:14px;padding:9px 11px;border:1px solid var(--line);border-radius:11px;background:var(--panel);box-shadow:var(--shadow)}.tc-tools input{min-width:240px;flex:1}.tc-tools .label{font-weight:700;color:var(--green)}
.panel,.card{background:var(--panel);border:1px solid var(--line);border-radius:13px;box-shadow:var(--shadow);margin-bottom:16px}.panel{overflow:visible}.panel.pad,.pad{padding:17px}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:13px}.card{padding:17px;overflow:hidden}.card .value{font-size:29px;font-weight:750;letter-spacing:-.03em;color:var(--green)}h1,h2,h3{margin-top:0}h2{margin-bottom:12px}.panel.pad>h2,.panel.pad>h3{display:flex;gap:8px;align-items:center}.panel.pad>h2:before,.panel.pad>h3:before{content:"";display:inline-block;width:4px;height:20px;border-radius:99px;background:var(--green);flex:0 0 4px}
.tc-table-wrap{position:relative}.tc-table-tools{display:flex;gap:8px;align-items:center;flex-wrap:wrap;padding:9px;border-bottom:1px solid var(--line);background:var(--panel2);border-radius:12px 12px 0 0;position:relative;z-index:4}.tc-table-tools select{max-width:220px}.tc-filter-value{min-width:150px;flex:0 1 220px}.tc-table-tools input{min-width:180px;flex:1}.tc-colbox{position:relative}.tc-colmenu{display:none;position:absolute;right:0;top:calc(100% + 5px);z-index:100;width:230px;max-height:350px;overflow:auto;background:var(--panel);border:1px solid var(--line);border-radius:9px;padding:8px;box-shadow:0 14px 35px rgba(0,0,0,.28)}.tc-colbox.open .tc-colmenu{display:block}.tc-colmenu label{display:flex;gap:8px;align-items:center;padding:6px}.tc-scroll{overflow:auto;max-width:100%;border-radius:0 0 12px 12px}table{width:100%;border-collapse:collapse;min-width:800px}th,td{padding:12px 14px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top}th{font-size:11px;text-transform:uppercase;color:var(--muted);background:var(--panel2);position:sticky;top:0;z-index:2;cursor:pointer;white-space:nowrap}th[data-sort]::after{content:" ↕";opacity:.35}tbody tr:nth-child(even){background:color-mix(in srgb,var(--panel2) 25%,transparent)}tbody tr:hover{background:color-mix(in srgb,var(--green) 6%,transparent)}.tc-count{font-size:12px;color:var(--muted);white-space:nowrap}.login{max-width:440px;margin:70px auto}
@media(max-width:1180px){.tc-head{grid-template-columns:190px 1fr}.tc-brand,.tc-brand a{width:180px;min-width:180px}.tc-logo{width:175px!important}.tc-account{grid-column:2;justify-self:end}.tc-nav{grid-column:2}}
@media(max-width:820px){.tc-app{padding:9px 9px 34px}.tc-head{grid-template-columns:54px 1fr;padding:9px}.tc-brand,.tc-brand a{width:54px;min-width:54px}.tc-logo{display:none!important}.tc-icon{display:block}.tc-nav{grid-column:1/-1;order:3;flex-wrap:nowrap;overflow:auto}.tc-account span{display:none}.tc-tools{flex-wrap:wrap}.tc-tools input{min-width:100%}.cards{grid-template-columns:1fr}}
'''

JS = r'''
(function(){
 const root=document.documentElement;
 const saved=localStorage.getItem('tikcentral:theme');
 root.dataset.theme=saved||(matchMedia('(prefers-color-scheme: light)').matches?'light':'dark');
 function themeLabel(){const b=document.getElementById('tcTheme');if(b)b.textContent=root.dataset.theme==='light'?'Dark mode':'Light mode'}
 window.tcToggleTheme=function(){root.dataset.theme=root.dataset.theme==='light'?'dark':'light';localStorage.setItem('tikcentral:theme',root.dataset.theme);themeLabel()};
 async function tcWriteClipboard(text){
   text=String(text??'');
   try{
     if(navigator.clipboard&&window.isSecureContext){await navigator.clipboard.writeText(text);return true}
   }catch(_){}
   try{
     const ta=document.createElement('textarea');ta.value=text;ta.setAttribute('readonly','');ta.style.position='fixed';ta.style.opacity='0';ta.style.pointerEvents='none';document.body.appendChild(ta);ta.select();ta.setSelectionRange(0,ta.value.length);const ok=document.execCommand('copy');ta.remove();return !!ok
   }catch(_){return false}
 }
 window.tcCopy=async function(valueOrElement,button){
   let text='';
   if(valueOrElement&&typeof valueOrElement==='object'){
     if('value' in valueOrElement)text=valueOrElement.value;
     else text=valueOrElement.innerText||valueOrElement.textContent||'';
   }else text=String(valueOrElement??'');
   const ok=await tcWriteClipboard(text);
   if(button){
     const old=button.textContent;button.textContent=ok?'Copied':'Copy failed';button.classList.toggle('tc-copy-ok',ok);
     setTimeout(()=>{button.textContent=old;button.classList.remove('tc-copy-ok')},1200);
   }
   return ok;
 };
 function installCopyButtons(rootNode=document){
   const rootEl=(rootNode&&rootNode.querySelectorAll)?rootNode:document;
   const fields=[...rootEl.querySelectorAll('input,textarea,select')].filter(el=>{
     const type=(el.getAttribute('type')||'text').toLowerCase();
     return !['hidden','checkbox','radio','submit','button','file'].includes(type)&&!el.dataset.noCopy&&el.id!=='tcGlobalSearch';
   });
   if(rootNode&&rootNode.matches&&rootNode.matches('input,textarea,select'))fields.unshift(rootNode);
   fields.forEach(el=>{
     const type=(el.getAttribute('type')||'text').toLowerCase();
     if(['hidden','checkbox','radio','submit','button','file'].includes(type)||el.dataset.noCopy||el.id==='tcGlobalSearch'||el.dataset.tcCopyReady)return;
     el.dataset.tcCopyReady='1';
     const b=document.createElement('button');b.type='button';b.className='tc-copy-btn';b.textContent='Copy';b.title='Copy field value';b.setAttribute('aria-label','Copy field value');
     b.addEventListener('click',e=>{e.preventDefault();e.stopPropagation();window.tcCopy(el,b)});el.insertAdjacentElement('afterend',b);
   });
   const copyables=[...rootEl.querySelectorAll('[data-copy],code.tc-copy,pre.tc-copy')];
   if(rootNode&&rootNode.matches&&rootNode.matches('[data-copy],code.tc-copy,pre.tc-copy'))copyables.unshift(rootNode);
   copyables.forEach(el=>{
     if(el.dataset.tcCopyReady)return;el.dataset.tcCopyReady='1';
     const b=document.createElement('button');b.type='button';b.className='tc-copy-btn';b.textContent='Copy';b.title='Copy value';
     b.addEventListener('click',e=>{e.preventDefault();e.stopPropagation();window.tcCopy(el,b)});el.insertAdjacentElement('afterend',b);
   });
 }
 document.addEventListener('click',e=>{const b=e.target.closest('[data-copy-target]');if(!b)return;const t=document.querySelector(b.dataset.copyTarget);if(t)window.tcCopy(t,b)});
 function numeric(s){const v=Number(String(s).replace(/[^0-9+-.]/g,''));return Number.isFinite(v)?v:null}
 function sortTable(table,idx,dir){const tb=table.tBodies[0];if(!tb)return;const rows=[...tb.rows];rows.sort((a,b)=>{let x=(a.cells[idx]?.innerText||'').trim(),y=(b.cells[idx]?.innerText||'').trim();const nx=numeric(x),ny=numeric(y);let c=(nx!==null&&ny!==null)?nx-ny:x.localeCompare(y,undefined,{numeric:true,sensitivity:'base'});return dir*c});rows.forEach(r=>tb.appendChild(r))}
 function comparable(v){const s=String(v??'').trim();const n=Number(s.replace(/[%,$\s]/g,''));if(s&&Number.isFinite(n))return {type:'number',value:n};const d=Date.parse(s);if(s&&Number.isFinite(d)&&/[-/:T]/.test(s))return {type:'date',value:d};return {type:'text',value:s.toLowerCase()}}
 function matchOperator(cell,op,wanted){const raw=String(cell??'').trim();const a=comparable(raw),b=comparable(wanted);if(op==='contains')return raw.toLowerCase().includes(String(wanted??'').toLowerCase());if(op==='!contains')return !raw.toLowerCase().includes(String(wanted??'').toLowerCase());let av=a.value,bv=b.value;if(a.type!==b.type){av=raw.toLowerCase();bv=String(wanted??'').toLowerCase()}if(op==='=')return av===bv;if(op==='!=')return av!==bv;if(op==='>')return av>bv;if(op==='>=')return av>=bv;if(op==='<')return av<bv;if(op==='<=')return av<=bv;return true}
 function filterTable(wrap){const q=(wrap.querySelector('.tc-local-search')?.value||'').toLowerCase();const col=Number(wrap.querySelector('.tc-filter-column')?.value??-1);const op=wrap.querySelector('.tc-filter-op')?.value||'contains';const wanted=wrap.querySelector('.tc-filter-value')?.value||'';let shown=0,total=0;wrap.querySelectorAll('tbody tr').forEach(r=>{total++;const textOk=!q||(r.innerText||'').toLowerCase().includes(q);const filterOk=!wanted||col<0||matchOperator(r.cells[col]?.innerText||'',op,wanted);const ok=textOk&&filterOk;r.style.display=ok?'':'none';if(ok)shown++});const c=wrap.querySelector('.tc-count');if(c)c.textContent=shown+' of '+total+' rows'}
 function enhanceTable(table,index){if(table.dataset.tcReady)return;table.dataset.tcReady='1';const panel=table.parentElement;const wrap=document.createElement('div');wrap.className='tc-table-wrap';panel.insertBefore(wrap,table);const tools=document.createElement('div');tools.className='tc-table-tools';tools.innerHTML='<input class="tc-local-search" data-no-copy placeholder="Search this table…"><select class="tc-filter-column" data-no-copy title="Filter column"></select><select class="tc-filter-op" data-no-copy title="Filter operator"><option value="contains">contains</option><option value="!contains">does not contain</option><option value="=">=</option><option value="!=">!=</option><option value=">">&gt;</option><option value=">=">&gt;=</option><option value="<">&lt;</option><option value="<=">&lt;=</option></select><input class="tc-filter-value" data-no-copy placeholder="Filter value…"><span class="tc-count"></span><div class="tc-colbox"><button type="button" class="tc-colbtn">Columns ▾</button><div class="tc-colmenu"></div></div><button type="button" class="tc-reset">Reset view</button>';wrap.appendChild(tools);const scroll=document.createElement('div');scroll.className='tc-scroll';wrap.appendChild(scroll);scroll.appendChild(table);const key='tikcentral:columns:'+location.pathname+':'+index;let hidden=[];try{hidden=JSON.parse(localStorage.getItem(key)||'[]')}catch(_){hidden=[]}const headers=[...table.querySelectorAll('thead th')];const menu=tools.querySelector('.tc-colmenu');const filterColumn=tools.querySelector('.tc-filter-column');headers.forEach((th,i)=>{th.dataset.sort='1';let dir=1;th.addEventListener('click',e=>{if(e.target.closest('input,button,select'))return;sortTable(table,i,dir);dir*=-1});const label=(th.innerText||('Column '+(i+1))).trim()||('Column '+(i+1));const opt=document.createElement('option');opt.value=String(i);opt.textContent=label;filterColumn.appendChild(opt);const row=document.createElement('label');row.innerHTML='<input type="checkbox" '+(hidden.includes(i)?'':'checked')+'><span></span>';row.querySelector('span').textContent=label;const cb=row.querySelector('input');cb.addEventListener('change',()=>setCol(i,cb.checked));menu.appendChild(row);setCol(i,!hidden.includes(i),false)});function setCol(i,show,save=true){[...table.rows].forEach(r=>{if(r.cells[i])r.cells[i].style.display=show?'':'none'});hidden=hidden.filter(x=>x!==i);if(!show)hidden.push(i);if(save)localStorage.setItem(key,JSON.stringify(hidden))}tools.querySelector('.tc-colbtn').onclick=e=>{e.stopPropagation();tools.querySelector('.tc-colbox').classList.toggle('open')};tools.querySelector('.tc-local-search').oninput=()=>filterTable(wrap);filterColumn.onchange=()=>filterTable(wrap);tools.querySelector('.tc-filter-op').onchange=()=>filterTable(wrap);tools.querySelector('.tc-filter-value').oninput=()=>filterTable(wrap);tools.querySelector('.tc-reset').onclick=()=>{tools.querySelector('.tc-local-search').value='';tools.querySelector('.tc-filter-value').value='';tools.querySelector('.tc-filter-op').value='contains';if(filterColumn.options.length)filterColumn.selectedIndex=0;hidden=[];localStorage.removeItem(key);headers.forEach((_,i)=>setCol(i,true,false));menu.querySelectorAll('input').forEach(x=>x.checked=true);filterTable(wrap)};filterTable(wrap)}
 function globalFilter(){const q=(document.getElementById('tcGlobalSearch')?.value||'').toLowerCase();document.querySelectorAll('.panel,.card').forEach(el=>{if(el.querySelector('.tc-table-wrap'))return;el.style.display=!q||(el.innerText||'').toLowerCase().includes(q)?'':'none'});document.querySelectorAll('.tc-table-wrap').forEach(w=>{const inp=w.querySelector('.tc-local-search');if(inp){inp.value=q;filterTable(w)}})}
 document.addEventListener('click',()=>document.querySelectorAll('.tc-colbox.open').forEach(x=>x.classList.remove('open')));
 document.addEventListener('keydown',e=>{if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==='k'){e.preventDefault();document.getElementById('tcGlobalSearch')?.focus()}if(e.key==='Escape'&&document.activeElement===document.getElementById('tcGlobalSearch')){document.getElementById('tcGlobalSearch').value='';globalFilter()}});
 document.addEventListener('DOMContentLoaded',()=>{themeLabel();installCopyButtons();const observer=new MutationObserver(mutations=>{mutations.forEach(m=>m.addedNodes.forEach(node=>{if(node.nodeType===1)installCopyButtons(node)}))});observer.observe(document.body,{childList:true,subtree:true});document.querySelectorAll('table').forEach(enhanceTable);const g=document.getElementById('tcGlobalSearch');if(g)g.addEventListener('input',globalFilter);document.querySelectorAll('td').forEach(td=>{if(td.children.length)return;const s=(td.innerText||'').trim().toLowerCase();let tone='';if(['healthy','online','passed','success','succeeded','enabled','ready','commissioned','matches baseline'].includes(s))tone='ok';else if(['warning','partial','degraded','pending','queued','running','verifying','drift','drift detected'].includes(s))tone='warn';else if(['failed','error','critical','offline'].includes(s))tone='bad';if(tone){const text=td.innerText;td.innerHTML='<span class="tc-status '+tone+' live"><span class="tc-status-dot"></span><span></span></span>';td.firstChild.lastChild.textContent=text}})});
})();
'''


def page(title: str, body: str, user=None, active: str = "") -> HTMLResponse:
    active = active or _infer_active(title)
    nav = ""
    account = ""
    if user:
        try:
            email = user["email"]
            role = user["role"] if user["role"] in {"viewer", "technician", "admin"} else "viewer"
        except Exception:
            email, role = "admin", "admin"
        links = []
        for key, href, label in NAV:
            if role != "admin" and key in {"users", "settings", "ssh"}:
                continue
            cls = "active" if key == active else ""
            links.append(f'<a class="{cls}" href="{href}">{html.escape(label)}</a>')
        nav = '<nav class="tc-nav">' + ''.join(links) + '</nav>'
        account = f'<div class="tc-account"><span>{html.escape(email)} · {html.escape(role.title())}</span><a href="/account/password"><button type="button">Account</button></a><form method="post" action="/logout" style="display:inline"><button>Logout</button></form></div>'
    light = settings.ASSETS["logo_light"]
    dark = settings.ASSETS["logo_dark"]
    icon = settings.ASSETS["icon"]
    tools = '<div class="tc-tools"><span class="label">Search</span><input id="tcGlobalSearch" placeholder="Search this page…"><button type="button" onclick="document.getElementById(\'tcGlobalSearch\').value=\'\';document.getElementById(\'tcGlobalSearch\').dispatchEvent(new Event(\'input\'))">Clear</button><button id="tcTheme" type="button" onclick="tcToggleTheme()">Theme</button></div>' if user else ''
    localized = localize_html_iso_timestamps(body or "").replace(" UTC", " Montréal")
    html_doc = f'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{html.escape(title)} - Tikcentral</title><link rel="icon" href="{icon}"><script>(function(){{try{{document.documentElement.dataset.theme=localStorage.getItem('tikcentral:theme')||(matchMedia('(prefers-color-scheme: light)').matches?'light':'dark')}}catch(e){{document.documentElement.dataset.theme='dark'}}}})();</script><style>{CSS}</style></head><body><main class="tc-app"><header class="tc-head"><div class="tc-brand"><a href="/"><img class="tc-logo tc-logo-light" src="{light}" alt="Opticable"><img class="tc-logo tc-logo-dark" src="{dark}" alt="Opticable"><img class="tc-icon" src="{icon}" alt="Opticable"></a></div>{nav}{account}</header>{tools}{localized}</main><script>{JS}</script></body></html>'''
    return HTMLResponse(html_doc)
