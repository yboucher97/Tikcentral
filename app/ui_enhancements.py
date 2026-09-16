"""Shared authenticated Tikcentral UI enhancements.

This layer is intentionally client-side and generic so current and future modules
inherit the same table/search/theme behavior without each route duplicating UI
logic. Router/application data remains unchanged.
"""

from fastapi.responses import HTMLResponse


HEAD = r'''
<script>
(function(){
  try {
    const saved = localStorage.getItem('tikcentral:theme');
    const theme = saved || (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
    document.documentElement.dataset.theme = theme;
  } catch (_) {
    document.documentElement.dataset.theme = 'dark';
  }
})();
</script>
<style>
:root{
  --tc-bg:#0a0f1c;--tc-bg2:#0d1424;--tc-panel:#111a2b;--tc-panel2:#162137;
  --tc-line:#27354f;--tc-text:#eef4ff;--tc-muted:#97a6c0;--tc-accent:#6f9cff;
  --tc-accent2:#315aa3;--tc-danger:#e27482;--tc-danger-bg:#44232b;--tc-ok:#4bd486;
  --tc-input:#0c1425;--tc-code:#09111f;--tc-shadow:0 10px 30px rgba(0,0,0,.18);
  color-scheme:dark;
}
html[data-theme="light"]{
  --tc-bg:#f4f7fb;--tc-bg2:#edf2f8;--tc-panel:#ffffff;--tc-panel2:#f7f9fc;
  --tc-line:#d7dfeb;--tc-text:#172033;--tc-muted:#68758b;--tc-accent:#285cc4;
  --tc-accent2:#dfe9ff;--tc-danger:#b33646;--tc-danger-bg:#fff0f2;--tc-ok:#168a4a;
  --tc-input:#ffffff;--tc-code:#f4f6fa;--tc-shadow:0 8px 28px rgba(24,39,75,.08);
  color-scheme:light;
}
html,body{background:var(--tc-bg)!important;color:var(--tc-text)!important}
body{background:linear-gradient(180deg,var(--tc-bg2) 0,var(--tc-bg) 260px)!important;min-height:100vh}
main{max-width:1800px!important;padding-top:14px!important}
a{color:var(--tc-accent)!important}
.shell-head{position:sticky!important;top:0;z-index:50;background:color-mix(in srgb,var(--tc-bg) 88%,transparent)!important;backdrop-filter:blur(14px);padding:12px 10px!important;margin:0 -10px 16px!important;border-bottom:1px solid var(--tc-line)!important}
.brand h1{letter-spacing:-.03em}.sub,.muted{color:var(--tc-muted)!important}
.topnav{gap:5px!important}.topnav a{color:var(--tc-muted)!important;border:1px solid transparent;transition:.15s ease}.topnav a:hover{background:var(--tc-panel2)!important;color:var(--tc-text)!important}.topnav a.active{background:var(--tc-accent2)!important;color:var(--tc-text)!important;border-color:color-mix(in srgb,var(--tc-accent) 38%,var(--tc-line))!important}
.panel,.card{background:var(--tc-panel)!important;border-color:var(--tc-line)!important;box-shadow:var(--tc-shadow)}
.panel{border-radius:16px!important}.card{border-radius:16px!important;transition:transform .12s ease,border-color .12s ease}.card:hover{transform:translateY(-1px);border-color:color-mix(in srgb,var(--tc-accent) 35%,var(--tc-line))!important}
h2,h3{letter-spacing:-.015em}h3{margin-top:0}
button{background:var(--tc-panel2)!important;color:var(--tc-text)!important;border-color:var(--tc-line)!important;transition:transform .08s ease,border-color .12s ease,background .12s ease}button:hover:not(:disabled){transform:translateY(-1px);border-color:var(--tc-accent)!important}button.primary{background:var(--tc-accent2)!important;border-color:color-mix(in srgb,var(--tc-accent) 50%,var(--tc-line))!important}button.danger{background:var(--tc-danger-bg)!important;color:var(--tc-danger)!important;border-color:color-mix(in srgb,var(--tc-danger) 45%,var(--tc-line))!important}button:disabled{opacity:.5;cursor:not-allowed}
input,select,textarea{background:var(--tc-input)!important;color:var(--tc-text)!important;border-color:var(--tc-line)!important;outline:none;transition:border-color .12s ease,box-shadow .12s ease}input:focus,select:focus,textarea:focus{border-color:var(--tc-accent)!important;box-shadow:0 0 0 3px color-mix(in srgb,var(--tc-accent) 15%,transparent)}
pre,code{color:var(--tc-text)}pre{background:var(--tc-code)!important;border:1px solid var(--tc-line);border-radius:10px;padding:14px}.badge{background:var(--tc-panel2)!important;color:var(--tc-muted)!important;border:1px solid var(--tc-line)}
table{min-width:720px!important;background:transparent}th,td{border-bottom-color:var(--tc-line)!important}thead th{position:sticky;top:0;z-index:3;background:var(--tc-panel)!important;color:var(--tc-muted)!important;user-select:none}tbody tr{transition:background .1s ease}tbody tr:hover{background:color-mix(in srgb,var(--tc-accent) 6%,transparent)}
th.tc-sortable{cursor:pointer;padding-right:28px!important;position:sticky}th.tc-sortable::after{content:'↕';position:absolute;right:10px;opacity:.35;font-size:12px}th.tc-sort-asc::after{content:'▲';opacity:.9}th.tc-sort-desc::after{content:'▼';opacity:.9}
.tc-page-tools{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin:0 0 18px;padding:11px 12px;background:var(--tc-panel);border:1px solid var(--tc-line);border-radius:14px;box-shadow:var(--tc-shadow)}
.tc-page-search{flex:1;min-width:260px;max-width:720px}.tc-tool-spacer{flex:1}.tc-theme-btn{min-width:112px}
.tc-table-tools{display:flex;align-items:center;gap:8px;flex-wrap:wrap;padding:10px 12px;border-bottom:1px solid var(--tc-line);background:color-mix(in srgb,var(--tc-panel2) 62%,var(--tc-panel))}.tc-table-search{min-width:240px;max-width:520px;flex:1}.tc-table-count{font-size:12px;color:var(--tc-muted);white-space:nowrap}.tc-table-shell{overflow:auto;max-width:100%}
.tc-columns{position:relative}.tc-columns-menu{display:none;position:absolute;z-index:30;right:0;top:calc(100% + 6px);min-width:220px;max-height:360px;overflow:auto;background:var(--tc-panel);border:1px solid var(--tc-line);border-radius:12px;box-shadow:var(--tc-shadow);padding:8px}.tc-columns.open .tc-columns-menu{display:block}.tc-columns-menu label{display:flex;gap:8px;align-items:center;padding:7px 8px;border-radius:7px;white-space:nowrap}.tc-columns-menu label:hover{background:var(--tc-panel2)}
.tc-search-hidden{display:none!important}.tc-no-results td{text-align:center;color:var(--tc-muted);padding:20px}.tc-toolbar-label{font-size:12px;color:var(--tc-muted);font-weight:600;text-transform:uppercase;letter-spacing:.04em}
.error{background:var(--tc-danger-bg)!important;border-color:color-mix(in srgb,var(--tc-danger) 45%,var(--tc-line))!important;color:var(--tc-text)}
@media(max-width:900px){.shell-head{position:relative!important}.tc-page-tools{position:sticky;top:0;z-index:45}.tc-page-search{min-width:100%;max-width:none}.tc-tool-spacer{display:none}.account{width:100%}.topnav{overflow:auto;flex-wrap:nowrap;padding-bottom:3px}.topnav a{white-space:nowrap}.panel.pad{padding:15px!important}}
@media(max-width:620px){main{padding:10px 8px 36px!important}.tc-table-tools{align-items:stretch}.tc-table-search{min-width:100%;max-width:none}.tc-columns{margin-left:auto}.cards{grid-template-columns:1fr 1fr!important;gap:9px!important}.card{padding:14px!important}}
</style>
'''


SCRIPT = r'''
<script>
(function(){
  const $=(s,r=document)=>r.querySelector(s), $$=(s,r=document)=>Array.from(r.querySelectorAll(s));
  const norm=s=>(s||'').toString().toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g,'').trim();
  const storage={get(k,d){try{const v=localStorage.getItem(k);return v===null?d:JSON.parse(v)}catch(_){return d}},set(k,v){try{localStorage.setItem(k,JSON.stringify(v))}catch(_){}}};

  function applyTheme(theme){
    document.documentElement.dataset.theme=theme;
    try{localStorage.setItem('tikcentral:theme',theme)}catch(_){}
    const b=$('#tcTheme'); if(b){b.textContent=theme==='dark'?'☀ Light mode':'☾ Dark mode';b.title='Switch appearance';}
  }

  function addPageTools(){
    const head=$('.shell-head'); if(!head||$('#tcPageTools')) return;
    const bar=document.createElement('div'); bar.id='tcPageTools'; bar.className='tc-page-tools';
    bar.innerHTML='<span class="tc-toolbar-label">Search page</span><input id="tcGlobalSearch" class="tc-page-search" type="search" autocomplete="off" placeholder="Search this page…"><button type="button" id="tcGlobalClear">Clear</button><span class="tc-tool-spacer"></span><button type="button" id="tcTheme" class="tc-theme-btn"></button>';
    head.insertAdjacentElement('afterend',bar);
    applyTheme(document.documentElement.dataset.theme||'dark');
    $('#tcTheme').addEventListener('click',()=>applyTheme(document.documentElement.dataset.theme==='dark'?'light':'dark'));
    $('#tcGlobalClear').addEventListener('click',()=>{const x=$('#tcGlobalSearch');x.value='';x.dispatchEvent(new Event('input'));x.focus();});
    $('#tcGlobalSearch').addEventListener('input',()=>applyGlobalSearch());
  }

  function cellValue(row,i){const c=row.cells[i];return norm(c?c.innerText:'')}
  function sortableValue(v){
    const compact=v.replace(/[, ]/g,'');
    if(/^[-+]?\d+(?:\.\d+)?%?$/.test(compact)) return {type:'n',v:parseFloat(compact)};
    const ip=v.match(/^\d{1,3}(?:\.\d{1,3}){3}$/); if(ip) return {type:'s',v};
    return {type:'s',v};
  }
  function compare(a,b){if(a.type==='n'&&b.type==='n')return a.v-b.v;return a.v.localeCompare(b.v,undefined,{numeric:true,sensitivity:'base'});}

  function tableKey(table,index,headers){return 'tikcentral:columns:'+location.pathname+':'+index+':'+encodeURIComponent(headers.join('|')).slice(0,220)}
  function applyHiddenColumns(table,hidden){
    $$('tr',table).forEach(row=>Array.from(row.cells).forEach((cell,i)=>{cell.hidden=hidden.includes(i)}));
  }
  function updateCount(state){
    const visible=state.rows.filter(r=>!r.classList.contains('tc-search-hidden')).length;
    state.count.textContent=visible+' of '+state.rows.length+' rows';
  }
  function applyTableFilter(state){
    const local=norm(state.search.value), global=norm(($('#tcGlobalSearch')||{}).value||'');
    state.rows.forEach(row=>{const hay=norm(row.innerText);row.classList.toggle('tc-search-hidden',!!((local&&!hay.includes(local))||(global&&!hay.includes(global))))});
    updateCount(state);
  }

  const tableStates=[];
  function enhanceTable(table,index){
    if(table.dataset.tcEnhanced==='1'||!table.tHead||!table.tBodies.length)return;
    table.dataset.tcEnhanced='1';
    const headers=Array.from(table.tHead.rows[0]?.cells||[]).map((h,i)=>h.innerText.trim()||('Column '+(i+1)));
    if(!headers.length)return;
    const body=table.tBodies[0];
    const rows=Array.from(body.rows).filter(r=>r.cells.length>1&&!Array.from(r.cells).some(c=>c.colSpan>1));
    const panel=table.closest('.panel')||table.parentElement;
    const shell=document.createElement('div');shell.className='tc-table-shell';
    table.parentNode.insertBefore(shell,table);shell.appendChild(table);
    const tools=document.createElement('div');tools.className='tc-table-tools';
    tools.innerHTML='<input class="tc-table-search" type="search" autocomplete="off" placeholder="Search this table…"><span class="tc-table-count"></span><div class="tc-columns"><button type="button" class="tc-columns-btn">Columns ▾</button><div class="tc-columns-menu"></div></div><button type="button" class="tc-reset-table">Reset view</button>';
    shell.parentNode.insertBefore(tools,shell);
    const search=$('.tc-table-search',tools),count=$('.tc-table-count',tools),columns=$('.tc-columns',tools),menu=$('.tc-columns-menu',tools);
    const key=tableKey(table,index,headers); let hidden=storage.get(key,[]).filter(x=>Number.isInteger(x)&&x>=0&&x<headers.length);
    headers.forEach((name,i)=>{
      const label=document.createElement('label');label.innerHTML='<input type="checkbox" '+(!hidden.includes(i)?'checked':'')+'><span></span>';$('span',label).textContent=name;
      $('input',label).addEventListener('change',e=>{hidden=e.target.checked?hidden.filter(x=>x!==i):Array.from(new Set(hidden.concat(i)));storage.set(key,hidden);applyHiddenColumns(table,hidden)});menu.appendChild(label);
    });
    applyHiddenColumns(table,hidden);
    $('.tc-columns-btn',tools).addEventListener('click',e=>{e.stopPropagation();columns.classList.toggle('open')});
    $('.tc-reset-table',tools).addEventListener('click',()=>{search.value='';hidden=[];storage.set(key,hidden);$$('input[type=checkbox]',menu).forEach(x=>x.checked=true);applyHiddenColumns(table,hidden);Array.from(table.tHead.rows[0].cells).forEach(h=>h.classList.remove('tc-sort-asc','tc-sort-desc'));applyTableFilter(state)});
    Array.from(table.tHead.rows[0].cells).forEach((th,i)=>{
      if(!th.innerText.trim())return;th.classList.add('tc-sortable');th.title='Click to sort';
      th.addEventListener('click',e=>{if(e.target.closest('button,input,label'))return;const asc=!th.classList.contains('tc-sort-asc');Array.from(table.tHead.rows[0].cells).forEach(h=>h.classList.remove('tc-sort-asc','tc-sort-desc'));th.classList.add(asc?'tc-sort-asc':'tc-sort-desc');const sorted=rows.slice().sort((ra,rb)=>compare(sortableValue(cellValue(ra,i)),sortableValue(cellValue(rb,i)))*(asc?1:-1));sorted.forEach(r=>body.appendChild(r));});
    });
    const state={table,rows,search,count,panel};tableStates.push(state);search.addEventListener('input',()=>applyTableFilter(state));updateCount(state);
  }

  function applyGlobalSearch(){
    tableStates.forEach(applyTableFilter);
    const q=norm(($('#tcGlobalSearch')||{}).value||'');
    $$('.cards .card').forEach(el=>el.classList.toggle('tc-search-hidden',!!(q&&!norm(el.innerText).includes(q))));
    $$('.panel').filter(p=>!p.querySelector('table')).forEach(el=>el.classList.toggle('tc-search-hidden',!!(q&&!norm(el.innerText).includes(q))));
  }

  document.addEventListener('click',e=>{if(!e.target.closest('.tc-columns'))$$('.tc-columns.open').forEach(x=>x.classList.remove('open'))});
  document.addEventListener('keydown',e=>{
    if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==='k'){e.preventDefault();const x=$('#tcGlobalSearch');if(x){x.focus();x.select();}}
    if(e.key==='Escape'){const x=$('#tcGlobalSearch');if(x&&document.activeElement===x){x.value='';x.dispatchEvent(new Event('input'));x.blur();}}
  });
  document.addEventListener('DOMContentLoaded',()=>{addPageTools();$$('table').forEach(enhanceTable);applyGlobalSearch();});
})();
</script>
'''


def enhance_response(response: HTMLResponse) -> HTMLResponse:
    """Inject shared UI controls into an authenticated HTML response."""
    text = response.body.decode("utf-8")
    if "tikcentral:columns:" in text:
        return response
    if "</head>" in text:
        text = text.replace("</head>", HEAD + "</head>", 1)
    if "</body>" in text:
        text = text.replace("</body>", SCRIPT + "</body>", 1)
    return HTMLResponse(text, status_code=response.status_code, headers=dict(response.headers))
