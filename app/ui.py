"""Single HTML renderer for all Tikcentral pages."""

import html

from fastapi.responses import HTMLResponse

from app import settings
from app.ui_time import localize_html_iso_timestamps

NAV_GROUPS = [
    ("Overview", [
        ("dashboard", "/", "Dashboard"),
        ("alerts", "/alerts", "Alerts"),
        ("training", "/training", "Training"),
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
CATEGORY_SLUG = {
    "Overview":"overview",
    "Fleet":"fleet",
    "Operations":"operations",
    "Changes":"changes",
    "Intelligence":"intelligence",
    "Administration":"administration",
    "Workspace":"workspace",
}

CATEGORY_HOME = {
    "Overview":"/",
    "Fleet":"/routers",
    "Operations":"/operations",
    "Changes":"/changes",
    "Intelligence":"/config-search",
    "Administration":"/system-health",
    "Workspace":"/",
}

PAGE_GUIDANCE = {
    "dashboard": ("Fleet overview", "Start here: current fleet health, exceptions and operator access."),
    "alerts": ("Exceptions", "Acknowledge, assign and resolve issues that need operator attention."),
    "training": ("Training", "Learn Tikcentral through short practical missions and track exactly what you have completed."),
    "routers": ("Inventory", "Find a router, check health, then open its workspace for troubleshooting or changes."),
    "fleet-search": ("Fleet search", "Search operational inventory across the whole MikroTik fleet."),
    "customers": ("Customer view", "Move from customer → site → router without losing operational context."),
    "cross-site-anomalies": ("Correlation", "Look for failures affecting multiple sites or providers at the same time."),
    "operations": ("Router workspace", "Use this for day-to-day router health, troubleshooting and safe actions."),
    "guardian": ("Management path", "Monitor and recover Tikcentral management reachability."),
    "reliability": ("Reliability", "Review availability, transactions and recovery evidence."),
    "compliance": ("Policy", "Compare routers against the expected Tikcentral management baseline."),
    "rescue": ("Recovery", "Use controlled rescue access only when normal management is unavailable."),
    "automation": ("Automation", "Run standard fleet maintenance and analysis jobs."),
    "ssh": ("Advanced", "Direct RouterOS shell access. Prefer structured Tikcentral actions when available."),
    "changes": ("Change history", "Understand what changed, who changed it and the measured impact."),
    "change-calendar": ("Planning", "Schedule and track planned operational changes."),
    "maintenance-automation": ("Post-change", "Control automatic verification after successful router changes."),
    "upgrade-campaigns": ("Upgrades", "Plan canary approval and staged RouterOS upgrade campaigns."),
    "replacements": ("Replacement", "Transfer site intent and metadata to a newly enrolled router safely."),
    "lifecycle": ("Lifecycle", "Track routers from commissioning through production, maintenance and retirement."),
    "config-search": ("Configuration intelligence", "Search retained RouterOS configuration snapshots across the fleet."),
    "audit": ("Router audit", "Inspect configuration and management-policy differences."),
    "operator-audit": ("Operator history", "Review who performed administrative actions in Tikcentral."),
    "enroll": ("Enrollment", "Add a MikroTik router and generate its one-time enrollment script."),
    "retention": ("Data lifecycle", "Control how long Tikcentral keeps each class of operational history."),
    "system-health": ("Tikcentral health", "Verify services, backups and core management dependencies."),
    "database-health": ("Database", "Monitor SQLite storage growth and capacity risk."),
    "users": ("Access control", "Manage Tikcentral users, roles and account availability."),
    "settings": ("Administration", "Account and platform settings."),
}

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
body.tc-compact .tc-content{padding-top:14px}body.tc-compact .panel.pad,body.tc-compact .pad{padding:11px}body.tc-compact .card{padding:10px}body.tc-compact th,body.tc-compact td{padding:7px 9px}body.tc-compact .cards{gap:7px}body.tc-compact .panel,body.tc-compact .card{margin-bottom:9px}

.tc-shell{--section-accent:var(--accent);--section-soft:var(--accent-soft)}
.tc-cat-overview{--section-accent:#45bd7a;--section-soft:color-mix(in srgb,#45bd7a 12%,transparent)}
.tc-cat-fleet{--section-accent:#4d98e8;--section-soft:color-mix(in srgb,#4d98e8 12%,transparent)}
.tc-cat-operations{--section-accent:#36b6aa;--section-soft:color-mix(in srgb,#36b6aa 12%,transparent)}
.tc-cat-changes{--section-accent:#d7a84d;--section-soft:color-mix(in srgb,#d7a84d 12%,transparent)}
.tc-cat-intelligence{--section-accent:#9b7de0;--section-soft:color-mix(in srgb,#9b7de0 12%,transparent)}
.tc-cat-administration{--section-accent:#7f8b84;--section-soft:color-mix(in srgb,#7f8b84 12%,transparent)}
html[data-theme="light"] .tc-cat-overview{--section-accent:#21865a}
html[data-theme="light"] .tc-cat-fleet{--section-accent:#2e72b8}
html[data-theme="light"] .tc-cat-operations{--section-accent:#167e75}
html[data-theme="light"] .tc-cat-changes{--section-accent:#986813}
html[data-theme="light"] .tc-cat-intelligence{--section-accent:#6d53ad}
html[data-theme="light"] .tc-cat-administration{--section-accent:#5e6962}
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
.tc-nav-group{margin:8px 0 3px;border-radius:9px;border:1px solid transparent}.tc-nav-label{list-style:none;cursor:pointer;padding:7px 10px;color:var(--muted);font-size:10px;letter-spacing:.10em;text-transform:uppercase;font-weight:800;border-radius:8px}.tc-nav-label::-webkit-details-marker{display:none}.tc-nav-label:after{content:"›";float:right;font-size:14px;line-height:10px;transition:transform .14s}.tc-nav-group[open]>.tc-nav-label:after{transform:rotate(90deg)}.tc-nav-label:hover{background:var(--surface2);color:var(--text)}
.tc-nav-group[open]{border-color:color-mix(in srgb,var(--section-accent) 20%,var(--line));background:color-mix(in srgb,var(--section-soft) 55%,transparent)}.tc-nav-group[open]>.tc-nav-label{color:var(--section-accent);background:color-mix(in srgb,var(--section-soft) 70%,transparent)}

.tc-nav-overview{--group-accent:#45bd7a;--group-soft:color-mix(in srgb,#45bd7a 11%,transparent)}
.tc-nav-fleet{--group-accent:#4d98e8;--group-soft:color-mix(in srgb,#4d98e8 11%,transparent)}
.tc-nav-operations{--group-accent:#36b6aa;--group-soft:color-mix(in srgb,#36b6aa 11%,transparent)}
.tc-nav-changes{--group-accent:#d7a84d;--group-soft:color-mix(in srgb,#d7a84d 11%,transparent)}
.tc-nav-intelligence{--group-accent:#9b7de0;--group-soft:color-mix(in srgb,#9b7de0 11%,transparent)}
.tc-nav-administration{--group-accent:#7f8b84;--group-soft:color-mix(in srgb,#7f8b84 11%,transparent)}
.tc-nav-group[class*="tc-nav-"][open]{border-color:color-mix(in srgb,var(--group-accent) 24%,var(--line));background:var(--group-soft)}
.tc-nav-group[class*="tc-nav-"][open]>.tc-nav-label{color:var(--group-accent);background:color-mix(in srgb,var(--group-soft) 72%,transparent)}
.tc-nav-group[class*="tc-nav-"] .tc-nav a.active{background:var(--group-soft);box-shadow:inset 3px 0 0 var(--group-accent)}
.tc-nav{display:grid;gap:2px;margin:2px 5px 6px}.tc-nav a{display:flex;align-items:center;min-height:36px;padding:8px 10px;border-radius:8px;color:var(--muted);font-weight:650}
.tc-nav a:hover{background:var(--surface2);color:var(--text)}.tc-nav a.active{background:var(--section-soft);color:var(--text);box-shadow:inset 3px 0 0 var(--section-accent);font-weight:760}
.tc-sidebar-foot{margin-top:18px;padding:12px 8px 0;border-top:1px solid var(--line);font-size:12px;color:var(--muted)}
.tc-main{min-width:0}.tc-topbar{position:sticky;top:0;z-index:25;height:64px;display:flex;align-items:center;gap:12px;padding:0 22px;background:color-mix(in srgb,var(--bg) 88%,transparent);backdrop-filter:blur(12px);border-bottom:1px solid color-mix(in srgb,var(--section-accent) 24%,var(--line));box-shadow:inset 0 -2px 0 color-mix(in srgb,var(--section-accent) 34%,transparent)}
.tc-menu-btn{display:none}.tc-page-meta{min-width:0;flex:1}.tc-page-title{font-size:17px;font-weight:780;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.tc-breadcrumb{font-size:11px;color:var(--muted);margin-top:2px}
.tc-top-actions{display:flex;align-items:center;gap:8px}.tc-command-btn{min-width:220px;text-align:left;color:var(--muted);display:flex;justify-content:space-between;gap:12px}.tc-kbd{font-size:10px;border:1px solid var(--line);background:var(--surface3);padding:2px 5px;border-radius:5px;color:var(--muted)}
.tc-account{position:relative}.tc-account>button{max-width:210px}.tc-account-menu{display:none;position:absolute;right:0;top:calc(100% + 7px);width:240px;background:var(--surface);border:1px solid var(--line);border-radius:10px;box-shadow:var(--shadow);padding:8px;z-index:80}.tc-account.open .tc-account-menu{display:block}.tc-account-menu a,.tc-account-menu form{display:block}.tc-account-menu button{width:100%;text-align:left;border:0;background:transparent}
.tc-content{max-width:var(--content);margin:0 auto;padding:22px 24px 56px}
.tc-page-tools{display:flex;gap:8px;align-items:center;margin-bottom:16px}.tc-page-tools input{flex:1;max-width:420px}.tc-page-tools .hint{margin-left:auto;color:var(--muted);font-size:11px}

.tc-page-intro{display:flex;justify-content:space-between;gap:14px;align-items:flex-start;padding:12px 14px;margin-bottom:12px;border:1px solid color-mix(in srgb,var(--section-accent) 22%,var(--line));border-left:4px solid var(--section-accent);border-radius:4px 10px 10px 4px;background:color-mix(in srgb,var(--section-soft) 60%,var(--surface2));color:var(--muted)}.tc-page-intro strong{display:block;color:var(--text);margin-bottom:2px}.tc-intro-dismiss{border:0;background:transparent;padding:0 4px;font-size:18px;color:var(--muted)}body.tc-hide-guidance .tc-page-intro{display:none}
.tc-contextbar{display:flex;align-items:center;gap:10px;flex-wrap:wrap;padding:10px 12px;margin-bottom:12px;border:1px solid color-mix(in srgb,var(--section-accent) 18%,var(--line));border-radius:10px;background:linear-gradient(90deg,color-mix(in srgb,var(--section-soft) 52%,var(--surface)),var(--surface) 28%)}.tc-context-main{display:flex;align-items:center;gap:8px;margin-right:auto}.tc-context-title{font-weight:780}.tc-context-links{display:flex;gap:5px;flex-wrap:wrap}.tc-context-links a{display:inline-flex;padding:6px 8px;border:1px solid var(--line);border-radius:7px;color:var(--muted);font-size:12px}.tc-context-links a:hover{background:var(--surface2);color:var(--text)}.tc-context-links a.active{background:var(--section-soft);color:var(--text);border-color:color-mix(in srgb,var(--section-accent) 38%,var(--line));box-shadow:inset 0 -2px 0 var(--section-accent)}
.tc-empty{padding:22px!important;text-align:center!important;color:var(--muted)!important;background:var(--surface2)}.tc-empty:before{content:"No data yet";display:block;color:var(--text);font-weight:750;margin-bottom:3px}
.tc-danger-action{border-color:color-mix(in srgb,var(--danger) 40%,var(--line))!important;color:var(--danger)!important}.tc-warning-action{border-color:color-mix(in srgb,var(--warn) 42%,var(--line))!important;color:var(--warn)!important}
.tc-dirty{box-shadow:0 0 0 2px color-mix(in srgb,var(--warn) 22%,transparent)}kbd{font:10px ui-monospace,SFMono-Regular,Menlo,monospace;border:1px solid var(--line);background:var(--surface3);border-bottom-width:2px;padding:1px 4px;border-radius:4px;color:var(--muted)}

.tc-smart-kind{display:inline-flex;align-items:center;padding:3px 7px;border-radius:999px;border:1px solid var(--line);font-size:10px;font-weight:850;letter-spacing:.02em;white-space:nowrap}.tc-smart-measure{color:#36b6aa;background:color-mix(in srgb,#36b6aa 10%,transparent);border-color:color-mix(in srgb,#36b6aa 30%,var(--line))}.tc-smart-compare{color:#4d98e8;background:color-mix(in srgb,#4d98e8 10%,transparent);border-color:color-mix(in srgb,#4d98e8 30%,var(--line))}.tc-smart-correlate{color:#9b7de0;background:color-mix(in srgb,#9b7de0 10%,transparent);border-color:color-mix(in srgb,#9b7de0 30%,var(--line))}.tc-smart-estimate{color:#d7a84d;background:color-mix(in srgb,#d7a84d 10%,transparent);border-color:color-mix(in srgb,#d7a84d 30%,var(--line))}.tc-smart-ai{color:#e37cab;background:color-mix(in srgb,#e37cab 10%,transparent);border-color:color-mix(in srgb,#e37cab 30%,var(--line))}.tc-smart-legend{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:8px;margin-top:14px}.tc-smart-legend>div{padding:10px;border:1px solid var(--line);border-radius:8px;background:var(--surface2)}.tc-smart-legend strong,.tc-smart-legend span{display:block}.tc-smart-legend span{color:var(--muted);font-size:12px;margin-top:2px}.tc-smart-card>summary{display:flex!important;align-items:center;gap:7px;flex-wrap:wrap}.tc-smart-explain{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px;margin-top:12px}.tc-smart-explain>div{padding:10px;border:1px solid var(--line);border-radius:8px;background:var(--surface2)}.tc-smart-explain strong,.tc-smart-explain span{display:block}.tc-smart-explain span{color:var(--muted);margin-top:3px}
.tc-training-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:9px;margin-top:12px}.tc-training-card{display:block;padding:12px;border:1px solid var(--line);border-radius:9px;background:var(--surface2);color:var(--text);transition:.14s}.tc-training-card:hover{border-color:color-mix(in srgb,var(--accent) 38%,var(--line));background:var(--accent-soft)}.tc-training-meta{margin-top:9px;color:var(--muted);font-size:11px}.tc-progress{height:7px;background:var(--surface3);border-radius:999px;overflow:hidden;margin-top:8px}.tc-progress>span{display:block;height:100%;background:var(--accent);border-radius:999px}.tc-mission-hero{border-left:3px solid var(--accent)}.tc-mission-list{list-style:none;padding:0;margin:0;display:grid;gap:8px}.tc-mission-list li{display:flex;gap:10px;align-items:flex-start;padding:9px;border:1px solid var(--line);background:var(--surface2);border-radius:8px}.tc-mission-step{display:inline-flex;align-items:center;justify-content:center;min-width:24px;height:24px;border-radius:50%;background:var(--accent-soft);color:var(--accent);font-weight:800}

.panel,.card{background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);box-shadow:none;margin-bottom:14px}

.tc-content details.panel{overflow:hidden;border-radius:11px}.tc-content details.panel>summary{list-style:none;cursor:pointer;padding:12px 14px;margin:-1px;border:1px solid transparent;border-radius:10px;background:var(--surface2);color:var(--text);font-weight:700}.tc-content details.panel>summary::-webkit-details-marker{display:none}.tc-content details.panel>summary:after{content:"+";float:right;display:inline-flex;align-items:center;justify-content:center;width:22px;height:22px;border-radius:6px;background:var(--surface3);color:var(--muted);font-size:15px}.tc-content details.panel[open]{border-color:color-mix(in srgb,var(--section-accent) 28%,var(--line));box-shadow:inset 3px 0 0 var(--section-accent)}.tc-content details.panel[open]>summary{margin:0;border-radius:8px 8px 0 0;background:var(--section-soft);color:var(--section-accent);border-bottom-color:color-mix(in srgb,var(--section-accent) 22%,var(--line))}.tc-content details.panel[open]>summary:after{content:"−";background:color-mix(in srgb,var(--section-accent) 15%,var(--surface3));color:var(--section-accent)}
.tc-content details.panel[open]>*:not(summary){margin-left:3px}

.tc-section-index{display:inline-flex;align-items:center;justify-content:center;width:20px;height:20px;margin-right:8px;border-radius:6px;background:color-mix(in srgb,var(--section-accent) 13%,var(--surface3));color:var(--section-accent);font-size:10px;font-weight:850;vertical-align:middle}.tc-content details.panel:not([open]) .tc-section-index{background:var(--surface3);color:var(--muted)}
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
.tc-filter-column,.tc-filter-op,.tc-date-column{max-width:220px}.tc-filter-value{min-width:150px;flex:0 1 240px}.tc-date-range{display:none;gap:7px;align-items:center;flex-wrap:wrap;width:100%;padding-top:8px}.tc-table-tools.has-date.filter-open .tc-date-range{display:flex}.tc-date-range label{display:flex;gap:5px;align-items:center;color:var(--muted);font-size:11px}.tc-date-range input{min-height:34px}.tc-timezone-hint{font-size:10px;color:var(--muted)}.tc-count{font-size:11px;color:var(--muted);white-space:nowrap;margin-left:auto}
.tc-colbox{position:relative}.tc-colmenu{display:none;position:absolute;right:0;top:calc(100% + 5px);z-index:100;width:270px;max-height:420px;overflow:auto;background:var(--surface);border:1px solid var(--line);border-radius:10px;padding:8px;box-shadow:var(--shadow)}.tc-colbox.open .tc-colmenu{display:block}.tc-colmenu label{display:flex;gap:8px;align-items:center;padding:6px;border-radius:6px}.tc-colmenu label:hover{background:var(--surface2)}.tc-colmenu-head{position:sticky;top:-8px;z-index:2;background:var(--surface);padding:8px 4px;border-bottom:1px solid var(--line);margin-bottom:4px}.tc-colmenu-actions{display:flex;gap:6px;margin-top:7px}.tc-colmenu-actions button{flex:1;padding:5px 7px;font-size:11px}.tc-view-saved{font-size:10px;color:var(--muted);margin-left:4px}
.tc-scroll{overflow:auto;max-width:100%;border-radius:0 0 11px 11px}table{width:100%;border-collapse:collapse;min-width:760px}th,td{padding:10px 12px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:10px;text-transform:uppercase;letter-spacing:.045em;color:var(--muted);background:var(--surface2);position:sticky;top:0;z-index:2;cursor:pointer;white-space:nowrap}th[data-sort]::after{content:" ↕";opacity:.3}
tbody tr:hover{background:var(--surface2)}

.tc-copy-btn{margin-left:5px;padding:3px 6px;font-size:10px}.tc-copy-ok{border-color:var(--accent)!important;color:var(--accent)!important}
td.tc-copyable-cell{position:relative;padding-right:48px}.tc-cell-copy{position:absolute;right:5px;top:5px;opacity:0;padding:2px 6px;font-size:9px;line-height:1.2;background:var(--surface3);z-index:3}.tc-copyable-cell:hover>.tc-cell-copy,.tc-cell-copy:focus{opacity:1}.tc-copy-priority>.tc-cell-copy{opacity:1;border-color:color-mix(in srgb,var(--accent) 55%,var(--line));color:var(--accent);font-weight:800}.tc-copy-table,.tc-copy-column{white-space:nowrap}
.tc-toast{border-left:3px solid var(--accent)}.tc-toast.bad{border-left-color:var(--danger)}
.tc-diff-line{padding:3px 9px;white-space:pre-wrap;word-break:break-word;border-bottom:1px solid color-mix(in srgb,var(--line) 45%,transparent)}.tc-diff-line.ok{background:color-mix(in srgb,var(--ok) 9%,transparent);color:var(--ok)}.tc-diff-line.bad{background:color-mix(in srgb,var(--danger) 9%,transparent);color:var(--danger)}.tc-diff-line.warn{background:color-mix(in srgb,var(--warn) 9%,transparent);color:var(--warn)}

.tc-palette{display:none;position:fixed;inset:0;background:rgba(0,0,0,.54);z-index:200;padding:9vh 18px}.tc-palette.open{display:block}.tc-palette-card{width:min(720px,100%);max-height:78vh;margin:auto;background:var(--surface);border:1px solid var(--line);border-radius:14px;box-shadow:0 24px 70px rgba(0,0,0,.38);overflow:hidden}.tc-palette-search{padding:13px;border-bottom:1px solid var(--line)}.tc-palette-search input{width:100%;font-size:15px}.tc-palette-list{max-height:60vh;overflow:auto;padding:7px}.tc-palette-group{padding:8px 10px 5px;color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:.1em;font-weight:800}.tc-palette-item{display:flex;justify-content:space-between;gap:15px;padding:9px 10px;border-radius:8px;color:var(--text)}.tc-palette-item:hover,.tc-palette-item.active{background:var(--accent-soft)}.tc-palette-item span:last-child{color:var(--muted);font-size:11px}

.tc-router-primary{display:flex;gap:7px;flex-wrap:wrap;margin-top:12px}.tc-router-toolbox{margin-top:10px}.tc-router-toolbox summary{cursor:pointer;color:var(--accent);font-weight:700}.tc-router-tool-groups{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:10px;margin-top:10px}.tc-router-tool-group{border:1px solid var(--line);border-left:3px solid color-mix(in srgb,var(--section-accent) 55%,var(--line));background:var(--surface2);border-radius:6px 9px 9px 6px;padding:9px}.tc-router-tool-group strong{display:block;margin-bottom:5px}.tc-router-tool-group a{display:flex;align-items:center;justify-content:space-between;gap:7px;padding:6px 3px;color:var(--muted)}.tc-router-tool-group a:hover{color:var(--text)}
.tc-workspace-tabs{display:flex;gap:5px;overflow:auto;margin:2px 0 12px;padding:5px;border:1px solid var(--line);border-radius:11px;background:var(--surface2)}.tc-workspace-tabs button{white-space:nowrap;border-color:transparent;background:transparent;border-radius:7px}.tc-workspace-tabs button:hover{background:var(--surface3)}.tc-workspace-tabs button.active{background:var(--section-soft);border-color:color-mix(in srgb,var(--section-accent) 36%,var(--line));color:var(--section-accent);box-shadow:inset 0 -3px 0 var(--section-accent);font-weight:760}
.tc-workspace-section.active{animation:tcSectionIn .12s ease-out}@keyframes tcSectionIn{from{opacity:.72;transform:translateY(2px)}to{opacity:1;transform:none}}

.tc-workspace-tabs button[data-tab="Summary"]{--tab-accent:#45bd7a;--tab-soft:color-mix(in srgb,#45bd7a 12%,transparent)}
.tc-workspace-tabs button[data-tab="Connectivity"]{--tab-accent:#4d98e8;--tab-soft:color-mix(in srgb,#4d98e8 12%,transparent)}
.tc-workspace-tabs button[data-tab="Configuration"]{--tab-accent:#9b7de0;--tab-soft:color-mix(in srgb,#9b7de0 12%,transparent)}
.tc-workspace-tabs button[data-tab="Assets"]{--tab-accent:#d7a84d;--tab-soft:color-mix(in srgb,#d7a84d 12%,transparent)}
.tc-workspace-tabs button[data-tab="Activity"]{--tab-accent:#7f8b84;--tab-soft:color-mix(in srgb,#7f8b84 12%,transparent)}
.tc-workspace-tabs button.active[data-tab]{background:var(--tab-soft);border-color:color-mix(in srgb,var(--tab-accent) 38%,var(--line));color:var(--tab-accent);box-shadow:inset 0 -3px 0 var(--tab-accent)}
.tc-tab-description{margin:-4px 0 12px;padding:8px 10px;border-left:3px solid var(--tab-description-accent,var(--section-accent));background:var(--surface2);border-radius:3px 8px 8px 3px;color:var(--muted);font-size:12px}
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
 .tc-contextbar{align-items:flex-start}.tc-context-main{width:100%}.tc-context-links{width:100%;overflow:auto;flex-wrap:nowrap}.tc-page-intro{font-size:12px}
 .tc-account>button span{display:none}.tc-logo{width:178px}.tc-table-tools .tc-local-search{min-width:100%}.tc-count{margin-left:0}
 table{min-width:680px}.tc-log{grid-template-columns:1fr}.tc-router-primary{display:grid;grid-template-columns:1fr 1fr}.tc-router-primary a button{width:100%}
 .tc-cell-copy{opacity:.65}.tc-copy-priority>.tc-cell-copy{opacity:1}.tc-date-range{align-items:flex-start}.tc-date-range label{width:100%}.tc-date-range input{flex:1}
 .tc-smart-explain{grid-template-columns:1fr}.tc-smart-card>summary .muted{width:100%}
}
@media(prefers-reduced-motion:reduce){*{scroll-behavior:auto!important;transition:none!important}}
'''

JS = r'''
(function(){
 const root=document.documentElement;
 const saved=localStorage.getItem('tikcentral:theme');
 root.dataset.theme=saved||(matchMedia('(prefers-color-scheme: light)').matches?'light':'dark');
 let tcUserPrefs={},tcPrefsCsrf='',tcPrefTimers={};

 function localPrefKey(key){const who=document.body?.dataset?.tcUser||'anonymous';return 'tikcentral:account-pref:'+who+':'+key}
 function prefGet(key,fallback){
   if(Object.prototype.hasOwnProperty.call(tcUserPrefs,key))return tcUserPrefs[key];
   try{const raw=localStorage.getItem(localPrefKey(key));if(raw!==null)return JSON.parse(raw)}catch(_){}
   return fallback;
 }
 function prefSet(key,value){
   tcUserPrefs[key]=value;
   try{if(value===null)localStorage.removeItem(localPrefKey(key));else localStorage.setItem(localPrefKey(key),JSON.stringify(value))}catch(_){}
   clearTimeout(tcPrefTimers[key]);
   tcPrefTimers[key]=setTimeout(async()=>{
     try{await fetch('/api/ui/preferences',{method:'PUT',credentials:'same-origin',headers:{'Content-Type':'application/json','X-CSRF-Token':tcPrefsCsrf},body:JSON.stringify({key,value})})}catch(_){}
   },250);
 }
 async function loadUserPreferences(){
   try{
     const r=await fetch('/api/ui/preferences',{credentials:'same-origin',cache:'no-store'});
     if(!r.ok)return;
     const data=await r.json();tcUserPrefs=data.preferences||{};tcPrefsCsrf=data.csrf||'';
     Object.entries(tcUserPrefs).forEach(([k,v])=>{try{localStorage.setItem(localPrefKey(k),JSON.stringify(v))}catch(_){}});
   }catch(_){}
 }
 function themeLabel(){const b=document.getElementById('tcTheme');if(b)b.textContent=root.dataset.theme==='light'?'Dark':'Light'}
 window.tcToggleTheme=function(){root.dataset.theme=root.dataset.theme==='light'?'dark':'light';localStorage.setItem('tikcentral:theme',root.dataset.theme);prefSet('ui:theme',root.dataset.theme);themeLabel()};

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
     if(['hidden','checkbox','radio','submit','button','file','password'].includes(type)||el.hasAttribute('data-no-copy')||['tcGlobalSearch','tcPaletteSearch'].includes(el.id)||el.dataset.tcCopyReady)return;
     el.dataset.tcCopyReady='1';const b=document.createElement('button');b.type='button';b.className='tc-copy-btn';b.textContent='Copy';b.title='Copy field value';
     b.onclick=e=>{e.preventDefault();e.stopPropagation();window.tcCopy(el,b)};el.insertAdjacentElement('afterend',b);
   });
   const copyables=[...rootEl.querySelectorAll('[data-copy],code:not([data-no-copy]),pre.tc-copy')];
   copyables.forEach(el=>{if(el.dataset.tcCopyReady)return;el.dataset.tcCopyReady='1';const b=document.createElement('button');b.type='button';b.className='tc-copy-btn';b.textContent='Copy';b.onclick=e=>{e.preventDefault();e.stopPropagation();window.tcCopy(el,b)};el.insertAdjacentElement('afterend',b)});
 }
 document.addEventListener('click',e=>{const b=e.target.closest('[data-copy-target]');if(!b)return;const t=document.querySelector(b.dataset.copyTarget);if(t)window.tcCopy(t,b)});

 function numeric(s){const v=Number(String(s).replace(/[^0-9+-.]/g,''));return Number.isFinite(v)?v:null}
 function localWallTime(s){
   const m=String(s??'').trim().match(/^(\d{4})-(\d{2})-(\d{2})(?:[ T](\d{2}):(\d{2})(?::(\d{2}))?)?/);
   if(!m)return null;
   return Number(m[1]+m[2]+m[3]+(m[4]||'00')+(m[5]||'00')+(m[6]||'00'));
 }
 function sortTable(table,idx,dir){const tb=table.tBodies[0];if(!tb)return;const rows=[...tb.rows];rows.sort((a,b)=>{let x=cellTextForCopy(a.cells[idx]||document.createElement('td')),y=cellTextForCopy(b.cells[idx]||document.createElement('td'));const dx=localWallTime(x),dy=localWallTime(y);if(dx!==null&&dy!==null)return dir*(dx-dy);const nx=numeric(x),ny=numeric(y);let cmp=(nx!==null&&ny!==null)?nx-ny:x.localeCompare(y,undefined,{numeric:true,sensitivity:'base'});return dir*cmp});rows.forEach(row=>tb.appendChild(row))}
 function comparable(v){const s=String(v??'').trim();const wall=localWallTime(s);if(wall!==null)return {type:'date',value:wall};const n=numeric(s);if(s&&n!==null)return {type:'number',value:n};return {type:'text',value:s.toLowerCase()}}
 function matchOperator(cell,op,wanted){const raw=String(cell??'').trim();if(op==='contains')return raw.toLowerCase().includes(String(wanted??'').toLowerCase());if(op==='!contains')return !raw.toLowerCase().includes(String(wanted??'').toLowerCase());const a=comparable(raw),b=comparable(wanted);let av=a.value,bv=b.value;if(a.type!==b.type){av=raw.toLowerCase();bv=String(wanted??'').toLowerCase()}return op==='='?av===bv:op==='!='?av!==bv:op==='>'?av>bv:op==='>='?av>=bv:op==='<'?av<bv:op==='<='?av<=bv:true}
 function isDateHeader(label){return /(^|\b)(time|date|timestamp|when|seen|created|updated|captured|checked|check|detected|started|finished|occurred|resolved|acknowledged|handshake|opened|closed|expires|expiry|approved|scheduled|generated|snapshot|start|end)(\b|$)/i.test(label)}
 function cellTextForCopy(td){const clone=td.cloneNode(true);clone.querySelectorAll('button,form,.tc-cell-copy,.tc-copy-btn').forEach(x=>x.remove());return (clone.innerText||clone.textContent||'').trim()}
 function installCellCopy(table,headers){
   const priority=/identity|model|serial|public ip|vpn ip|winbox|hostname|address|gateway|mac|ticket|source ip/i;
   const skip=/workflow|actions?|troubleshooting|controls?$/i;
   [...table.tBodies].flatMap(tb=>[...tb.rows]).forEach(row=>{
     [...row.cells].forEach((td,i)=>{
       const label=(headers[i]?.innerText||'').trim();
       if(!label||skip.test(label)||td.classList.contains('tc-empty')||td.querySelector(':scope > .tc-cell-copy'))return;
       const value=cellTextForCopy(td);if(!value||value==='-')return;
       td.classList.add('tc-copyable-cell');if(priority.test(label))td.classList.add('tc-copy-priority');
       const b=document.createElement('button');b.type='button';b.className='tc-cell-copy';b.textContent='Copy';b.title='Copy '+label;
       b.onclick=e=>{e.preventDefault();e.stopPropagation();window.tcCopy(cellTextForCopy(td),b)};td.appendChild(b);
     });
   });
 }
 function visibleTableRows(table){
   return [...table.tBodies].flatMap(tb=>[...tb.rows]).filter(r=>r.style.display!=='none');
 }
 function visibleColumnIndexes(table,headers){
   return headers.map((_,i)=>i).filter(i=>[...table.rows].some(r=>r.cells[i]&&r.cells[i].style.display!=='none'));
 }
 async function copyVisibleTable(table,headers,button){
   const cols=visibleColumnIndexes(table,headers);
   const lines=[cols.map(i=>(headers[i]?.innerText||('Column '+(i+1))).trim()).join('\t')];
   visibleTableRows(table).forEach(r=>lines.push(cols.map(i=>cellTextForCopy(r.cells[i]||document.createElement('td'))).join('\t')));
   await window.tcCopy(lines.join('\n'),button);
 }
 async function copyVisibleColumn(table,headers,index,button){
   if(index<0||!headers[index])return;
   const values=[(headers[index].innerText||('Column '+(index+1))).trim()];
   visibleTableRows(table).forEach(r=>values.push(cellTextForCopy(r.cells[index]||document.createElement('td'))));
   await window.tcCopy(values.join('\n'),button);
 }
 function filterTable(wrap){
   const q=(wrap.querySelector('.tc-local-search')?.value||'').toLowerCase();
   const col=Number(wrap.querySelector('.tc-filter-column')?.value??-1),op=wrap.querySelector('.tc-filter-op')?.value||'contains',wanted=wrap.querySelector('.tc-filter-value')?.value||'';
   const dateCol=Number(wrap.querySelector('.tc-date-column')?.value??-1),from=wrap.querySelector('.tc-date-from')?.value||'',to=wrap.querySelector('.tc-date-to')?.value||'';
   const fromVal=from?localWallTime(from):null,toVal=to?localWallTime(to):null;
   let shown=0,total=0;
   wrap.querySelectorAll('tbody tr').forEach(r=>{
     total++;const rowText=[...r.cells].map(cellTextForCopy).join(' ').toLowerCase();const textOk=!q||rowText.includes(q);
     const filterOk=!wanted||col<0||matchOperator(cellTextForCopy(r.cells[col]||document.createElement('td')),op,wanted);
     let dateOk=true;if(dateCol>=0&&(fromVal!==null||toVal!==null)){const v=localWallTime(cellTextForCopy(r.cells[dateCol]||document.createElement('td')));dateOk=v!==null&&(fromVal===null||v>=fromVal)&&(toVal===null||v<=toVal)}
     const ok=textOk&&filterOk&&dateOk;r.style.display=ok?'':'none';if(ok)shown++;
   });
   const count=wrap.querySelector('.tc-count');if(count)count.textContent=shown+' / '+total;
 }
 function viewPath(){return location.pathname.replace(/\/\d+(?=\/|$)/g,'/:id')}
 function defaultHiddenColumns(table){
   const raw=(table.dataset.defaultHidden||'').trim();
   if(!raw)return [];
   return raw.split(',').map(x=>x.trim()).filter(Boolean).map(Number).filter(Number.isFinite);
 }
 function tableViewKey(table,headers,index){
   if(table.dataset.viewKey)return 'table:'+table.dataset.viewKey;
   const signature=headers.map(h=>(h.innerText||'').trim().toLowerCase()).join('|').replace(/[^a-z0-9|:_ -]/g,'').slice(0,220);
   const panel=table.closest('.panel,details');const heading=(panel?.querySelector(':scope > h2,:scope > h3,:scope > summary')?.innerText||'').trim().toLowerCase().replace(/[^a-z0-9 _:-]/g,'').slice(0,100);
   return 'table:'+viewPath()+':'+(heading||('table-'+index))+':'+signature;
 }
 function enhanceTable(table,index){
   if(table.dataset.tcReady)return;table.dataset.tcReady='1';
   const panel=table.parentElement,wrap=document.createElement('div');wrap.className='tc-table-wrap';panel.insertBefore(wrap,table);
   const tools=document.createElement('div');tools.className='tc-table-tools';
   tools.innerHTML='<input class="tc-local-search" data-no-copy placeholder="Search rows…"><button type="button" class="tc-filter-toggle">Filter</button><span class="tc-count"></span><button type="button" class="tc-copy-table">Copy visible</button><div class="tc-colbox"><button type="button" class="tc-colbtn">Columns</button><div class="tc-colmenu"></div></div><button type="button" class="tc-reset">Clear filters</button><div class="tc-advanced"><select class="tc-filter-column" data-no-copy></select><select class="tc-filter-op" data-no-copy><option value="contains">contains</option><option value="!contains">does not contain</option><option value="=">=</option><option value="!=">!=</option><option value=">">&gt;</option><option value=">=">&gt;=</option><option value="<">&lt;</option><option value="<=">&lt;=</option></select><input class="tc-filter-value" data-no-copy placeholder="Filter value…"><button type="button" class="tc-copy-column">Copy selected column</button></div><div class="tc-date-range"><select class="tc-date-column" data-no-copy></select><label>From <input type="datetime-local" class="tc-date-from" data-no-copy></label><label>To <input type="datetime-local" class="tc-date-to" data-no-copy></label><span class="tc-timezone-hint">Montréal local time</span></div>';
   wrap.appendChild(tools);const scroll=document.createElement('div');scroll.className='tc-scroll';wrap.appendChild(scroll);scroll.appendChild(table);
   const headers=[...table.querySelectorAll('thead th')],menu=tools.querySelector('.tc-colmenu'),filterColumn=tools.querySelector('.tc-filter-column'),dateColumn=tools.querySelector('.tc-date-column');
   const defaults=defaultHiddenColumns(table),viewKey=tableViewKey(table,headers,index),savedHidden=prefGet(viewKey,null);
   const legacyKey='tikcentral:columns:'+location.pathname+':'+index;let legacyHidden=null;
   try{const raw=localStorage.getItem(legacyKey);legacyHidden=raw===null?null:JSON.parse(raw)}catch(_){}
   const legacyLooksLikeColumnZeroBug=defaults.length===0&&Array.isArray(legacyHidden)&&legacyHidden.length===1&&Number(legacyHidden[0])===0;
   let hidden=Array.isArray(savedHidden)?savedHidden.map(Number).filter(Number.isFinite):(Array.isArray(legacyHidden)&&!legacyLooksLikeColumnZeroBug?legacyHidden.map(Number).filter(Number.isFinite):defaults.slice());
   hidden=[...new Set(hidden)].filter(i=>i>=0&&i<headers.length);
   if(headers.length&&hidden.length>=headers.length)hidden=[];
   if(savedHidden===null&&Array.isArray(legacyHidden)){prefSet(viewKey,hidden.slice());try{localStorage.removeItem(legacyKey)}catch(_){}}
   const head=document.createElement('div');head.className='tc-colmenu-head';head.innerHTML='<strong>Visible columns</strong><div class="tc-view-saved">Saved to your account</div><div class="tc-colmenu-actions"><button type="button" class="tc-show-all">Show all</button><button type="button" class="tc-reset-columns">Reset defaults</button></div>';menu.appendChild(head);
   const dateIndexes=[];
   headers.forEach((th,i)=>{
     th.dataset.sort='1';let dir=1;th.onclick=e=>{if(e.target.closest('input,button,select'))return;sortTable(table,i,dir);dir*=-1};
     const label=(th.innerText||('Column '+(i+1))).trim()||('Column '+(i+1));
     const opt=document.createElement('option');opt.value=String(i);opt.textContent=label;filterColumn.appendChild(opt);
     if(isDateHeader(label)){const dopt=document.createElement('option');dopt.value=String(i);dopt.textContent=label;dateColumn.appendChild(dopt);dateIndexes.push(i)}
     const row=document.createElement('label');row.innerHTML='<input type="checkbox" '+(hidden.includes(i)?'':'checked')+'><span></span>';row.querySelector('span').textContent=label;const cb=row.querySelector('input');cb.onchange=()=>setCol(i,cb.checked);menu.appendChild(row);setCol(i,!hidden.includes(i),false);
   });
   if(dateIndexes.length)tools.classList.add('has-date');else tools.querySelector('.tc-date-range')?.remove();
   installCellCopy(table,headers);
   function syncColumnChecks(){menu.querySelectorAll('label input').forEach((cb,i)=>cb.checked=!hidden.includes(i))}
   function setCol(i,show,save=true){
     const visibleCount=headers.length-hidden.length;
     if(!show&&visibleCount<=1){syncColumnChecks();return}
     [...table.rows].forEach(r=>{if(r.cells[i])r.cells[i].style.display=show?'':'none'});
     hidden=hidden.filter(x=>x!==i);if(!show)hidden.push(i);hidden.sort((a,b)=>a-b);
     if(save)prefSet(viewKey,hidden.slice());
   }
   tools.querySelector('.tc-show-all').onclick=()=>{hidden=[];headers.forEach((_,i)=>setCol(i,true,false));syncColumnChecks();prefSet(viewKey,[])};
   tools.querySelector('.tc-reset-columns').onclick=()=>{hidden=defaults.slice();headers.forEach((_,i)=>setCol(i,!hidden.includes(i),false));syncColumnChecks();prefSet(viewKey,hidden.slice())};
   tools.querySelector('.tc-filter-toggle').onclick=()=>tools.classList.toggle('filter-open');
   tools.querySelector('.tc-copy-table').onclick=e=>{e.preventDefault();copyVisibleTable(table,headers,e.currentTarget)};
   tools.querySelector('.tc-copy-column').onclick=e=>{e.preventDefault();copyVisibleColumn(table,headers,Number(filterColumn.value??-1),e.currentTarget)};
   tools.querySelector('.tc-colbtn').onclick=e=>{e.stopPropagation();tools.querySelector('.tc-colbox').classList.toggle('open')};
   ['input','change'].forEach(ev=>{tools.querySelector('.tc-local-search').addEventListener(ev,()=>filterTable(wrap));tools.querySelector('.tc-filter-value').addEventListener(ev,()=>filterTable(wrap));tools.querySelector('.tc-date-from')?.addEventListener(ev,()=>filterTable(wrap));tools.querySelector('.tc-date-to')?.addEventListener(ev,()=>filterTable(wrap))});
   filterColumn.onchange=()=>filterTable(wrap);tools.querySelector('.tc-filter-op').onchange=()=>filterTable(wrap);if(dateColumn)dateColumn.onchange=()=>filterTable(wrap);
   tools.querySelector('.tc-reset').onclick=()=>{tools.querySelector('.tc-local-search').value='';tools.querySelector('.tc-filter-value').value='';tools.querySelector('.tc-filter-op').value='contains';if(tools.querySelector('.tc-date-from'))tools.querySelector('.tc-date-from').value='';if(tools.querySelector('.tc-date-to'))tools.querySelector('.tc-date-to').value='';filterTable(wrap)};
   filterTable(wrap);
 }

 function globalFilter(){const q=(document.getElementById('tcGlobalSearch')?.value||'').toLowerCase();const sections=[...document.querySelectorAll('.tc-workspace-section')];if(sections.length){if(q)sections.forEach(s=>s.classList.add('active'));else{sections.forEach(s=>s.classList.remove('active'));const active=document.querySelector('.tc-workspace-tabs button.active');const name=active?.textContent;if(name)document.querySelector('.tc-workspace-section[data-tab="'+CSS.escape(name)+'"]')?.classList.add('active')}}document.querySelectorAll('.tc-content .panel,.tc-content .card').forEach(el=>{if(el.querySelector('.tc-table-wrap'))return;el.style.display=!q||(el.innerText||'').toLowerCase().includes(q)?'':'none'});document.querySelectorAll('.tc-table-wrap').forEach(w=>{const inp=w.querySelector('.tc-local-search');if(inp){inp.value=q;filterTable(w)}})}

 function openPalette(){const p=document.getElementById('tcPalette');if(!p)return;p.classList.add('open');const i=document.getElementById('tcPaletteSearch');if(i){i.value='';filterPalette();setTimeout(()=>i.focus(),0)}}
 function closePalette(){document.getElementById('tcPalette')?.classList.remove('open')}
 function filterPalette(){const q=(document.getElementById('tcPaletteSearch')?.value||'').trim().toLowerCase();document.querySelectorAll('.tc-palette-item').forEach(x=>x.style.display=!q||(x.dataset.search||'').includes(q)?'flex':'none')}

 const smartKind=(href)=>{
   if(/\/ai\//.test(href))return 'AI';
   if(/cross-site|incidents|log-patterns|network-quality/.test(href))return 'Correlate';
   if(/capacity|local-utilization/.test(href))return 'Estimate';
   if(/changes|desired-state|compliance|public-ip-analysis|identity-collisions|hardware-lifecycle|model-capabilities/.test(href))return 'Compare';
   if(/wan-probe|interfaces|lte|mtu|time-health|traffic|diagnostics|security-audit/.test(href))return 'Measure';
   return '';
 };
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
       const box=details.querySelector('.tc-router-tool-groups');Object.entries(groups).forEach(([name,items])=>{const d=document.createElement('div');d.className='tc-router-tool-group';d.innerHTML='<strong>'+name+'</strong>';items.forEach(a=>{const copy=a.cloneNode(true);const href=copy.getAttribute('href')||'';const btn=copy.querySelector('button');if(btn){const label=btn.textContent;copy.textContent=label}const kind=smartKind(href);if(kind){const badge=document.createElement('span');badge.className='tc-smart-kind tc-smart-'+kind.toLowerCase();badge.textContent=kind;copy.appendChild(badge)}d.appendChild(copy)});box.appendChild(d)});hero.appendChild(details);
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
     if(
       el===hero ||
       el.id==='tcObjectContext' ||
       el.classList?.contains('tc-page-intro') ||
       el.classList?.contains('tc-page-tools') ||
       el.classList?.contains('tc-workspace-tabs') ||
       el.classList?.contains('tc-tab-description') ||
       el.classList?.contains('tc-workspace-section')
     )return;
     // Only reorganize the router page's operational content. Shared shell/context
     // elements must stay fixed above the workspace.
     if(!el.classList?.contains('panel') && !el.classList?.contains('cards'))return;
     const h=el.querySelector?.(':scope > h3');const title=h?.textContent?.trim()||'';
     let dest='';for(const [name,titles] of Object.entries(categoryMap)){if(titles.includes(title)){dest=name;break}}
     if(dest)sections[dest].appendChild(el);else leftovers.push(el);
   });
   const activity=document.createElement('div');activity.className='tc-workspace-section';activity.dataset.tab='Activity';leftovers.forEach(el=>activity.appendChild(el));sections.Activity=activity;
   const tabHelp={
     'Summary':'Identity, lifecycle, management access and the fastest health overview.',
     'Connectivity':'WAN, DNS, interfaces, traffic, LTE, topology and path-quality evidence.',
     'Configuration':'Security, policy, desired state, automation and RouterOS configuration evidence.',
     'Assets':'Hardware and model lifecycle information.',
     'Activity':'Backups, jobs, operator notes, events and historical operational activity.'
   };
   const tabColors={'Summary':'#45bd7a','Connectivity':'#4d98e8','Configuration':'#9b7de0','Assets':'#d7a84d','Activity':'#7f8b84'};
   const tabs=document.createElement('div');tabs.className='tc-workspace-tabs';
   const desc=document.createElement('div');desc.className='tc-tab-description';
   Object.keys(sections).forEach((name,i)=>{const b=document.createElement('button');b.type='button';b.textContent=name;b.dataset.tab=name;b.className=i===0?'active':'';b.onclick=()=>{tabs.querySelectorAll('button').forEach(x=>x.classList.remove('active'));b.classList.add('active');Object.values(sections).forEach(s=>s.classList.remove('active'));sections[name].classList.add('active');desc.textContent=tabHelp[name]||'';desc.style.setProperty('--tab-description-accent',tabColors[name]||'var(--section-accent)');localStorage.setItem('tikcentral:router-tab',name);prefSet('ui:router-tab',name)};tabs.appendChild(b)});
   hero.insertAdjacentElement('afterend',tabs);tabs.insertAdjacentElement('afterend',desc);Object.values(sections).forEach(s=>content.appendChild(s));
   const saved=prefGet('ui:router-tab',localStorage.getItem('tikcentral:router-tab'));const target=sections[saved]?saved:Object.keys(sections)[0];[...tabs.children].find(b=>b.textContent===target)?.click();
 }

 function routerIdFromPath(){
   const patterns=[
     /^\/(?:operations|timeline|incidents|diagnostics|network-quality|wan-probe|interfaces|lte|mtu|time-health|traffic|capacity|site|notes|customer-report|topology|desired-state|protection|recovery|security-audit|automation-inventory|local-utilization|public-ip-analysis|hardware|hardware-lifecycle|certificates|commissioning-checklist|maintenance-history|log-patterns|changes|ai|audit|compliance|lifecycle)\/(\d+)(?:\/|$)/
   ];
   for(const rx of patterns){const m=location.pathname.match(rx);if(m)return m[1]}
   return null;
 }
 function installRouterContext(){
   const id=routerIdFromPath(),mount=document.getElementById('tcObjectContext');if(!id||!mount)return;
   let label='Router #'+id;
   const heading=[...document.querySelectorAll('.tc-content h2,.tc-content h1')].map(x=>(x.textContent||'').trim()).find(Boolean);
   if(heading){
     const cleaned=heading.replace(/^(Router operations|Network quality|Router timeline|Incident builder|Site \/ customer|Hardware lifecycle|Interface health|LTE|MTU \/ MSS|Time \/ NTP health|Public-IP change analysis|Local network utilization|Router log patterns|Topology|Desired state|Security exposure|Certificates|Maintenance history)\s*[·:-]\s*/i,'').trim();
     if(cleaned&&cleaned.length<100)label=cleaned;
   }
   const links=[
     ['Overview','/operations/'+id],
     ['Timeline','/timeline/'+id],
     ['Incident','/incidents/'+id],
     ['Network','/network-quality/'+id],
     ['Site','/site/'+id],
     ['Notes','/notes/'+id],
     ['Changes','/changes/'+id],
     ['AI','/ai/'+id],
   ];
   const htmlLinks=links.map(([name,href])=>'<a href="'+href+'" class="'+(location.pathname===href?'active':'')+'">'+name+'</a>').join('');
   mount.innerHTML='<div class="tc-contextbar"><div class="tc-context-main"><span class="tc-status-dot" style="color:var(--accent)"></span><div><div class="tc-context-title"></div><div class="muted">Router workspace</div></div></div><div class="tc-context-links">'+htmlLinks+'</div></div>';
   mount.querySelector('.tc-context-title').textContent=label;
   try{
     const key=localPrefKey('ui:recent-routers');let recent=JSON.parse(localStorage.getItem(key)||'[]');
     recent=recent.filter(x=>String(x.id)!==String(id));recent.unshift({id,label,at:Date.now()});recent=recent.slice(0,8);localStorage.setItem(key,JSON.stringify(recent));prefSet('ui:recent-routers',recent);
   }catch(_){}
 }
 function installRecentRouters(){
   const list=document.querySelector('.tc-palette-list');if(!list)return;
   try{
     const recent=prefGet('ui:recent-routers',JSON.parse(localStorage.getItem(localPrefKey('ui:recent-routers'))||'[]'));if(!recent.length)return;
     const title=document.createElement('div');title.className='tc-palette-group';title.textContent='Recent routers';list.prepend(title);
     [...recent].reverse().forEach(x=>{const a=document.createElement('a');a.className='tc-palette-item';a.href='/operations/'+x.id;a.dataset.search=('router '+x.label+' '+x.id).toLowerCase();a.innerHTML='<span></span><span>Router</span>';a.firstChild.textContent=x.label;title.insertAdjacentElement('afterend',a)});
   }catch(_){}
 }
 function classifyActions(){
   document.querySelectorAll('button').forEach(b=>{
     const t=(b.textContent||'').trim().toLowerCase();
     if(/\b(delete|remove|retire|factory|destroy)\b/.test(t))b.classList.add('tc-danger-action');
     else if(/\b(reboot|upgrade|normalize|rescue|disable|rollback|replace)\b/.test(t))b.classList.add('tc-warning-action');
   });
 }
 function decorateEmptyStates(){
   document.querySelectorAll('tbody tr').forEach(tr=>{if(tr.children.length===1&&/^no\b/i.test((tr.innerText||'').trim()))tr.firstElementChild?.classList.add('tc-empty')});
 }
 function protectDirtyForms(){
   let dirty=false;
   const forms=[...document.querySelectorAll('form')].filter(f=>(f.method||'').toLowerCase()==='post'&&f.querySelector('input:not([type=hidden]):not([type=submit]),textarea,select'));
   forms.forEach(f=>{
     const mark=e=>{if(e.target.matches('input[type=search],input[data-no-copy]#tcGlobalSearch'))return;dirty=true;f.classList.add('tc-dirty')};
     f.addEventListener('input',mark);f.addEventListener('change',mark);f.addEventListener('submit',()=>{dirty=false;f.classList.remove('tc-dirty')});
   });
   window.addEventListener('beforeunload',e=>{if(dirty){e.preventDefault();e.returnValue=''}});
 }
 function installDisclosureState(){
   const details=[...document.querySelectorAll('.tc-content details.panel')];
   if(!details.length)return;
   details.forEach((d,i)=>{
     const label=(d.querySelector(':scope > summary')?.innerText||('section-'+i)).trim();
     const key='ui:disclosure:'+viewPath()+':'+label;
     const stored=prefGet(key,null);
     if(stored==='open')d.open=true;
     else if(stored==='closed')d.open=false;
     d.addEventListener('toggle',()=>prefSet(key,d.open?'open':'closed'));
   });
   if(details.length>=2){
     const tools=document.querySelector('.tc-page-tools');
     if(tools){
       const b=document.createElement('button');b.type='button';b.id='tcDisclosureToggle';
       const sync=()=>{const allOpen=details.every(d=>d.open);b.textContent=allOpen?'Collapse sections':'Expand sections';b.dataset.mode=allOpen?'collapse':'expand'};
       b.onclick=()=>{const open=b.dataset.mode==='expand';details.forEach(d=>{d.open=open});sync()};
       tools.appendChild(b);details.forEach(d=>d.addEventListener('toggle',sync));sync();
     }
   }
 }
 function emphasizeNestedSections(){
   document.querySelectorAll('.tc-content details.panel').forEach((d,i)=>{
     d.dataset.sectionIndex=String(i+1);
     const summary=d.querySelector(':scope > summary');
     if(summary && !summary.querySelector('.tc-section-index')){
       const n=document.createElement('span');n.className='tc-section-index';n.textContent=String(i+1);
       summary.prepend(n);
     }
   });
 }

 function installGuidancePreference(){
   const hidden=prefGet('ui:hide-guidance',localStorage.getItem('tikcentral:hide-guidance')==='1');
   const density=prefGet('ui:density',localStorage.getItem('tikcentral:density')||'comfortable');
   if(hidden)document.body.classList.add('tc-hide-guidance');
   if(density==='compact')document.body.classList.add('tc-compact');
   document.querySelector('.tc-intro-dismiss')?.addEventListener('click',()=>{document.body.classList.add('tc-hide-guidance');localStorage.setItem('tikcentral:hide-guidance','1');prefSet('ui:hide-guidance',true)});
   document.getElementById('tcRestoreGuidance')?.addEventListener('click',()=>{document.body.classList.remove('tc-hide-guidance');localStorage.removeItem('tikcentral:hide-guidance');prefSet('ui:hide-guidance',false)});
   document.getElementById('tcDensityToggle')?.addEventListener('click',()=>{document.body.classList.toggle('tc-compact');const d=document.body.classList.contains('tc-compact')?'compact':'comfortable';localStorage.setItem('tikcentral:density',d);prefSet('ui:density',d)});
 }

 function decorateStatuses(){document.querySelectorAll('td').forEach(td=>{if(td.children.length)return;const s=(td.innerText||'').trim().toLowerCase();let tone='';if(['healthy','online','passed','success','succeeded','enabled','ready','commissioned','matches baseline','ok','up'].includes(s))tone='ok';else if(['warning','partial','degraded','pending','queued','running','verifying','drift','drift detected','saturated'].includes(s))tone='warn';else if(['failed','error','critical','offline','down'].includes(s))tone='bad';if(tone){const text=td.innerText;td.innerHTML='<span class="tc-status '+tone+'"><span class="tc-status-dot"></span><span></span></span>';td.firstChild.lastChild.textContent=text}})}

 document.addEventListener('click',e=>{
   if(!e.target.closest('.tc-colbox'))document.querySelectorAll('.tc-colbox.open').forEach(x=>x.classList.remove('open'));
   if(!e.target.closest('.tc-account'))document.querySelector('.tc-account')?.classList.remove('open');
   if(e.target.id==='tcPalette')closePalette();
 });
 let tcGotoPrefix=false;
 document.addEventListener('keydown',e=>{
   const tag=(e.target?.tagName||'').toLowerCase();const typing=['input','textarea','select'].includes(tag)||e.target?.isContentEditable;
   if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==='k'){e.preventDefault();openPalette();return}
   if(e.key==='Escape'){closePalette();document.body.classList.remove('tc-nav-open');tcGotoPrefix=false;return}
   if(!typing&&e.key==='/'){e.preventDefault();document.getElementById('tcGlobalSearch')?.focus();return}
   if(!typing&&e.key.toLowerCase()==='g'){tcGotoPrefix=true;setTimeout(()=>tcGotoPrefix=false,1200);return}
   if(!typing&&tcGotoPrefix){
     const map={r:'/routers',a:'/alerts',o:'/operations',c:'/customers',d:'/'},dest=map[e.key.toLowerCase()];
     tcGotoPrefix=false;if(dest){e.preventDefault();location.href=dest}
   }
 });
 document.addEventListener('DOMContentLoaded',async()=>{
   await loadUserPreferences();
   const preferredTheme=prefGet('ui:theme',null);if(preferredTheme==='light'||preferredTheme==='dark')root.dataset.theme=preferredTheme;
   themeLabel();installCopyButtons();installGuidancePreference();installRouterContext();installRecentRouters();organizeRouterWorkspace();emphasizeNestedSections();installDisclosureState();decorateStatuses();decorateEmptyStates();classifyActions();protectDirtyForms();
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
    localized = localize_html_iso_timestamps(body or "")
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
                if role != "admin" and key in {"users", "settings", "ssh", "enroll"}:
                    continue
                cls = "active" if key == active else ""
                links.append(f'<a class="{cls}" href="{href}">{html.escape(label)}</a>')
                palette.append(f'<a class="tc-palette-item" href="{href}" data-search="{html.escape((group+" "+label).lower())}"><span>{html.escape(label)}</span><span>{html.escape(group)}</span></a>')
            if links:
                opened = " open" if group in {"Overview", category} else ""
                group_slug = CATEGORY_SLUG.get(group, "workspace")
                groups.append(f'<details class="tc-nav-group tc-nav-{group_slug}"{opened}><summary class="tc-nav-label">{html.escape(group)}</summary><nav class="tc-nav">{"".join(links)}</nav></details>')
        sidebar = "".join(groups)
        palette.append('<a class="tc-palette-item" href="/training/intelligence-guide" data-search="smart intelligence analysis explain compare correlate estimate ai help"><span>Smart Features Map</span><span>Training</span></a>')
        palette_items = "".join(palette)
        account = f'''<div class="tc-account"><button type="button" id="tcAccountBtn"><span>{html.escape(email)}</span> ▾</button><div class="tc-account-menu"><div style="padding:8px 10px"><strong>{html.escape(email)}</strong><div class="muted">{html.escape(role.title())}</div></div><a href="/account/password"><button type="button">Account & password</button></a><a href="/training"><button type="button">Training & progress</button></a><button type="button" id="tcDensityToggle">Toggle compact density</button><button type="button" id="tcRestoreGuidance">Show page tips</button><form method="post" action="/logout"><button>Sign out</button></form></div></div>'''
    guide_title, guide_text = PAGE_GUIDANCE.get(active, (category, "Use page search or Ctrl/⌘ K to move quickly through Tikcentral."))
    page_intro = f'<div class="tc-page-intro"><div><strong>{html.escape(guide_title)}</strong><div>{html.escape(guide_text)}</div></div><button type="button" class="tc-intro-dismiss" title="Hide page guidance">×</button></div>'
    page_tools = '<div class="tc-page-tools"><input id="tcGlobalSearch" data-no-copy placeholder="Search this page…"><button type="button" id="tcPageSearchClear">Clear</button><span class="hint"><kbd>/</kbd> search · <kbd>Ctrl/⌘ K</kbd> go to</span></div>' if user else ''
    category_slug = CATEGORY_SLUG.get(category, "workspace")
    shell = f'''<div class="tc-shell tc-cat-{category_slug}" data-workflow="{html.escape(category_slug)}">
<aside class="tc-sidebar" id="tcSidebar"><div class="tc-brand"><a href="/"><img class="tc-logo tc-logo-light" src="{light}" alt="Opticable"><img class="tc-logo tc-logo-dark" src="{dark}" alt="Opticable"><img class="tc-icon" src="{icon}" alt="Opticable"></a></div>{sidebar}<div class="tc-sidebar-foot">Tikcentral · Opticable<br>Management plane</div></aside>
<div class="tc-main"><header class="tc-topbar"><button class="tc-menu-btn" id="tcMenuBtn" type="button">☰</button><div class="tc-page-meta"><div class="tc-page-title">{html.escape(title)}</div><div class="tc-breadcrumb"><a href="{CATEGORY_HOME.get(category,'/')}" style="color:var(--section-accent);font-weight:750">{html.escape(category)}</a> · {html.escape(guide_title)}</div></div>
<div class="tc-top-actions">{f'<button class="tc-command-btn" id="tcCommandBtn" type="button"><span class="tc-command-label">Go to…</span><span class="tc-kbd">Ctrl K</span></button><a href="/training/intelligence-guide"><button type="button" title="Simple explanations for Tikcentral intelligence">Smart help</button></a><button id="tcTheme" type="button" onclick="tcToggleTheme()">Theme</button>{account}' if user else ''}</div></header>
<main class="tc-content">{page_intro}<div id="tcObjectContext"></div>{page_tools}{localized}</main></div></div>'''
    palette = f'''<div class="tc-palette" id="tcPalette"><div class="tc-palette-card"><div class="tc-palette-search"><input id="tcPaletteSearch" data-no-copy placeholder="Go to a feature…"></div><div class="tc-palette-list">{palette_items}</div></div></div>''' if user else ""
    user_scope = ""
    if user:
        try:
            user_scope = str(user["id"])
        except Exception:
            try:
                user_scope = str(user["email"])
            except Exception:
                user_scope = "authenticated"
    html_doc = f'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{html.escape(title)} - Tikcentral</title><link rel="icon" href="{icon}"><script>(function(){{try{{document.documentElement.dataset.theme=localStorage.getItem('tikcentral:theme')||(matchMedia('(prefers-color-scheme: light)').matches?'light':'dark')}}catch(e){{document.documentElement.dataset.theme='dark'}}}})();</script><style>{CSS}</style></head><body data-tc-user="{html.escape(user_scope)}">{shell}{palette}<script>{JS}</script></body></html>'''
    return HTMLResponse(html_doc)
