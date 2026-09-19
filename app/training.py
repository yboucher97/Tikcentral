"""Interactive, game-like Tikcentral training with persistent per-user progress."""

import html
from datetime import datetime, timezone

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app import main as core, migrations


LESSONS = [
    {
        "id":"start-dashboard","track":"Foundations","title":"Read the Dashboard","xp":100,"minutes":3,
        "why":"Learn the fastest way to decide what needs attention before opening individual routers.",
        "objective":"Identify fleet health, open alerts, and the Attention section.",
        "steps":["Open Dashboard.","Read Managed routers and Management healthy.","Open Alerts if any are present.","Review the Attention list before drilling into a router."],
        "route":"/","cta":"Open Dashboard",
    },
    {
        "id":"find-router","track":"Foundations","title":"Find and Open a Router","xp":100,"minutes":3,
        "why":"Build the muscle memory for moving from fleet inventory to a single router workspace.",
        "objective":"Find one router and open its Operations workspace.",
        "steps":["Open Routers.","Use row search or filters to find a site.","Click Open.","Notice the persistent router context links."],
        "route":"/routers","cta":"Open Routers",
    },
    {
        "id":"command-palette","track":"Foundations","title":"Use Ctrl+K","xp":125,"minutes":2,
        "why":"The command launcher is the fastest way to reach features without memorizing the sidebar.",
        "objective":"Use Ctrl/⌘ K to jump to a feature.",
        "steps":["Press Ctrl+K or ⌘K.","Type a feature name such as alerts or retention.","Open the result.","Try one recent router from the launcher."],
        "route":"/","cta":"Go to Dashboard",
    },
    {
        "id":"router-summary","track":"Router Operations","title":"Read a Router Workspace","xp":125,"minutes":5,
        "why":"Learn where health, connectivity, configuration, assets, and activity live without scanning every tool.",
        "objective":"Review the router Summary and switch between workspace tabs.",
        "steps":["Open a router.","Read Summary first.","Switch to Connectivity.","Switch to Configuration.","Open All router tools and observe the grouped tool categories."],
        "route":"/operations","cta":"Open Router Operations",
    },
    {
        "id":"network-quality","track":"Router Operations","title":"Diagnose Network Quality","xp":150,"minutes":7,
        "why":"Correlate DNS, gateway, interface negotiation, WAN saturation, bufferbloat, and PPPoE evidence.",
        "objective":"Open Network Quality on a router and interpret the major evidence groups.",
        "steps":["Open a router workspace.","Choose Network quality.","Check ISP gateway state.","Review DNS resolver results.","Check WAN utilization and bufferbloat state.","Review PPPoE or interface negotiation evidence when present."],
        "route":"/operations","cta":"Choose a Router",
    },
    {
        "id":"timeline-incident","track":"Troubleshooting","title":"Timeline → Incident","xp":175,"minutes":8,
        "why":"Use evidence in chronological order before reaching for configuration changes.",
        "objective":"Open a router Timeline and then its Incident workspace.",
        "steps":["Open Timeline from the router context.","Look for events around the failure window.","Open Incident.","Compare WAN, management, configuration, and log evidence.","Use AI analysis only after reviewing the factual evidence."],
        "route":"/operations","cta":"Choose a Router",
    },
    {
        "id":"alerts","track":"Troubleshooting","title":"Work an Alert","xp":125,"minutes":5,
        "why":"Learn the operator workflow from new alert through acknowledgement, assignment, investigation, and resolution.",
        "objective":"Open the Alert Queue and understand the alert statuses.",
        "steps":["Open Alerts.","Locate a non-resolved alert if one exists.","Review severity, site, and summary.","Observe the acknowledgement/assignment controls.","Do not resolve a real alert unless the issue is actually resolved."],
        "route":"/alerts","cta":"Open Alerts",
    },
    {
        "id":"site-metadata","track":"Site & Customer","title":"Maintain Site Context","xp":100,"minutes":5,
        "why":"Good circuit and customer metadata makes WAN diagnostics, customer reporting, and replacement workflows more useful.",
        "objective":"Review a router's Site / customer page and understand the progressive sections.",
        "steps":["Open Site from a router context bar.","Review Site identity and Primary contact.","Expand Circuit & technical details.","Confirm where circuit download/upload speeds belong.","Expand Support notes."],
        "route":"/operations","cta":"Choose a Router",
    },
    {
        "id":"safe-change","track":"Changes","title":"Understand a Safe Change","xp":200,"minutes":8,
        "why":"Tikcentral wraps mutations with access checks, backups, transaction tracking, verification, and impact analysis.",
        "objective":"Review a completed change and its measured impact without making a production change.",
        "steps":["Open Changes.","Choose an attributed transaction if available.","Review semantic config diff.","Open Measured change impact.","Compare before/after metrics and remember that correlation does not prove causation."],
        "route":"/changes","cta":"Open Changes",
    },
    {
        "id":"desired-compliance","track":"Changes","title":"Desired State vs Compliance","xp":150,"minutes":6,
        "why":"Desired state describes site intent; compliance checks Tikcentral's management-policy baseline.",
        "objective":"Understand the difference between intent and policy verification.",
        "steps":["Open a router workspace.","Open Desired state from All router tools.","Review the current intent and audit result.","Open Compliance.","Compare the purpose of the two views."],
        "route":"/operations","cta":"Choose a Router",
    },
    {
        "id":"fleet-intelligence","track":"Fleet Intelligence","title":"Use Cross-Site Intelligence","xp":150,"minutes":6,
        "why":"Avoid troubleshooting many sites independently when evidence points to a shared provider or dependency issue.",
        "objective":"Review cross-site anomalies and fleet search.",
        "steps":["Open Cross-site.","Review any active/resolved correlations.","Open Fleet search.","Search for a shared ISP, model, or RouterOS version.","Notice how fleet evidence differs from single-router evidence."],
        "route":"/cross-site-anomalies","cta":"Open Cross-Site",
    },
    {
        "id":"recovery","track":"Recovery","title":"Know the Recovery Path","xp":200,"minutes":8,
        "why":"Recovery should be deliberate: verify management, inspect snapshots/backups, respect protected objects, and avoid blind rollback.",
        "objective":"Locate the recovery tools and understand when to use them.",
        "steps":["Open a router workspace.","Open All router tools → Lifecycle & recovery.","Review Guided recovery.","Review Protected objects.","Locate Rescue, but do not enable it unless normal management is unavailable."],
        "route":"/operations","cta":"Choose a Router",
    },
    {
        "id":"admin-health","track":"Administration","title":"Verify Tikcentral Itself","xp":125,"minutes":5,
        "why":"A management platform must distinguish router problems from problems in its own services, database, or backups.",
        "objective":"Review System Health and Database Health.",
        "steps":["Open System health.","Check services and backup verification.","Open Database health.","Review free space and growth forecast.","Return to Dashboard."],
        "route":"/system-health","cta":"Open System Health",
    },
]

STATUS_LABELS={
    "not_started":"Not started",
    "in_progress":"In progress",
    "completed":"Completed",
    "skipped":"Skipped",
}


RANKS=[
    (0,"Explorer"),
    (400,"Operator"),
    (900,"Troubleshooter"),
    (1500,"Specialist"),
    (2200,"Tikcentral Expert"),
]


def _rank(xp):
    name=RANKS[0][1]
    next_at=None
    for threshold,label in RANKS:
        if xp>=threshold:
            name=label
        elif next_at is None:
            next_at=threshold
            break
    return name,next_at


def _track_slug(track):
    return track.lower().replace(" & ","-").replace(" ","-")


def _now():
    return datetime.now(timezone.utc).isoformat()


def _user_id(user):
    try:return int(user["id"])
    except Exception:return 0


def _lesson(lesson_id):
    return next((x for x in LESSONS if x["id"]==lesson_id),None)


def _progress(user_id):
    with core.db() as conn:
        rows=conn.execute("SELECT * FROM user_training_progress WHERE user_id=?",(user_id,)).fetchall()
    return {x["lesson_id"]:dict(x) for x in rows}


def _set_status(user_id,lesson_id,status):
    now=_now()
    with core.db() as conn:
        row=conn.execute("SELECT * FROM user_training_progress WHERE user_id=? AND lesson_id=?",(user_id,lesson_id)).fetchone()
        started=(row["started_at"] if row else "") or (now if status in {"in_progress","completed"} else "")
        completed=now if status=="completed" else ((row["completed_at"] if row and status=="completed" else "") if row else "")
        attempts=(int(row["attempts"] or 0) if row else 0)+(1 if status=="in_progress" else 0)
        conn.execute(
            """INSERT INTO user_training_progress(user_id,lesson_id,status,started_at,completed_at,attempts,updated_at)
               VALUES(?,?,?,?,?,?,?)
               ON CONFLICT(user_id,lesson_id) DO UPDATE SET status=excluded.status,started_at=excluded.started_at,
                 completed_at=excluded.completed_at,attempts=excluded.attempts,updated_at=excluded.updated_at""",
            (user_id,lesson_id,status,started,completed,attempts,now),
        )


def _stats(progress):
    total=len(LESSONS)
    completed=sum(1 for x in LESSONS if progress.get(x["id"],{}).get("status")=="completed")
    skipped=sum(1 for x in LESSONS if progress.get(x["id"],{}).get("status")=="skipped")
    started=sum(1 for x in LESSONS if progress.get(x["id"],{}).get("status")=="in_progress")
    xp=sum(int(x["xp"]) for x in LESSONS if progress.get(x["id"],{}).get("status")=="completed")
    percent=round(((completed+skipped)/total)*100) if total else 0
    return total,completed,skipped,started,xp,percent


def register(app,page_func):
    migrations.migrate()

    @app.get("/training",response_class=HTMLResponse)
    def training(request:Request):
        user=core.require_web_role(request,"viewer")
        if not user:return RedirectResponse("/login",303)
        uid=_user_id(user);progress=_progress(uid)
        total,completed,skipped,started,xp,percent=_stats(progress)
        rank,next_rank=_rank(xp)
        tracks=[]
        for track in dict.fromkeys(x["track"] for x in LESSONS):
            lessons=[x for x in LESSONS if x["track"]==track]
            done=sum(1 for x in lessons if progress.get(x["id"],{}).get("status") in {"completed","skipped"})
            cards=[]
            for lesson in lessons:
                st=progress.get(lesson["id"],{}).get("status","not_started")
                tone="ok" if st=="completed" else ("warn" if st in {"in_progress","skipped"} else "")
                badge=f'<span class="tc-status {tone}">{html.escape(STATUS_LABELS[st])}</span>' if tone else f'<span class="badge">{html.escape(STATUS_LABELS[st])}</span>'
                cards.append(f'''<a class="tc-training-card" href="/training/{lesson["id"]}">
<div class="inline" style="justify-content:space-between"><strong>{html.escape(lesson["title"])}</strong>{badge}</div>
<div class="muted" style="margin-top:6px">{html.escape(lesson["objective"])}</div>
<div class="tc-training-meta">{lesson["xp"]} XP · ~{lesson["minutes"]} min</div></a>''')
            track_complete=done==len(lessons)
            track_badge='<span class="tc-status ok">Track complete</span>' if track_complete else f'<span class="badge">{round(done*100/len(lessons)) if lessons else 0}%</span>'
            track_action='' if track_complete else f'''<form method="post" action="/training/track/{_track_slug(track)}/skip"><input type="hidden" name="csrf" value="{core.csrf_token(request)}"><button onclick="return confirm('Mark all unfinished lessons in {html.escape(track)} as already known?')">I know this track · Skip unfinished</button></form>'''
            tracks.append(f'''<div class="panel pad"><div class="inline" style="justify-content:space-between"><div><h3>{html.escape(track)}</h3><div class="muted">{done}/{len(lessons)} finished or skipped</div></div><div class="inline">{track_badge}{track_action}</div></div>
<div class="tc-training-grid">{"".join(cards)}</div></div>''')
        next_lesson=next((x for x in LESSONS if progress.get(x["id"],{}).get("status") not in {"completed","skipped"}),None)
        next_html=f'<a href="/training/{next_lesson["id"]}"><button class="primary">Continue: {html.escape(next_lesson["title"])}</button></a>' if next_lesson else '<span class="tc-status ok">Training path complete</span>'
        csrf=core.csrf_token(request)
        body=f'''<div class="cards">
<div class="card"><div class="muted">Training progress</div><div class="value">{percent}%</div><div class="tc-progress"><span style="width:{percent}%"></span></div></div>
<div class="card"><div class="muted">XP earned</div><div class="value">{xp}</div><div class="muted">Completed missions only</div></div>
<div class="card"><div class="muted">Rank</div><div class="value" style="font-size:20px">{html.escape(rank)}</div><div class="muted">{f'{next_rank-xp} XP to next rank' if next_rank is not None else 'Highest rank reached'}</div></div>
<div class="card"><div class="muted">Completed</div><div class="value">{completed}/{total}</div><div class="muted">{skipped} skipped · {started} in progress</div></div>
<div class="card"><div class="muted">Learning mode</div><div>Normal or Fast on every mission</div><div class="muted">Fast mode removes explanation, not progress tracking.</div></div>
</div>
<div class="panel pad"><div class="inline" style="justify-content:space-between"><div><h2>Tikcentral Training</h2><div>Short missions teach the actual workflow using the live interface. Nothing here changes router configuration automatically.</div></div>{next_html}</div>
<div class="muted" style="margin-top:8px">Completed = practiced. Skipped = you already know it. Both count toward path coverage; only completed missions earn XP.</div></div>
{"".join(tracks)}
<div class="panel pad"><h3>Progress controls</h3><div class="inline"><form method="post" action="/training/reset"><input type="hidden" name="csrf" value="{csrf}"><button class="tc-warning-action" onclick="return confirm('Reset all of your Tikcentral training progress?')">Reset my training</button></form></div></div>'''
        return page_func("Training",body,user,"training")

    @app.get("/training/{lesson_id}",response_class=HTMLResponse)
    def lesson_page(lesson_id:str,request:Request,mode:str="normal"):
        user=core.require_web_role(request,"viewer")
        if not user:return RedirectResponse("/login",303)
        lesson=_lesson(lesson_id)
        if not lesson:return RedirectResponse("/training",303)
        uid=_user_id(user);progress=_progress(uid);st=progress.get(lesson_id,{}).get("status","not_started")
        if st=="not_started":
            _set_status(uid,lesson_id,"in_progress");st="in_progress"
        fast=mode=="fast"
        idx=LESSONS.index(lesson)
        prev_l=LESSONS[idx-1] if idx>0 else None
        next_l=LESSONS[idx+1] if idx+1<len(LESSONS) else None
        csrf=core.csrf_token(request)
        steps="".join(f'<li><span class="tc-mission-step">{i}</span><span>{html.escape(step)}</span></li>' for i,step in enumerate(lesson["steps"],1))
        explanation="" if fast else f'''<div class="panel pad"><h3>Why this matters</h3><div>{html.escape(lesson["why"])}</div></div>
<div class="panel pad"><h3>Mission steps</h3><ol class="tc-mission-list">{steps}</ol></div>'''
        nav=[]
        if prev_l:nav.append(f'<a href="/training/{prev_l["id"]}?mode={"fast" if fast else "normal"}"><button>← Previous</button></a>')
        nav.append('<a href="/training"><button>Training map</button></a>')
        if next_l:nav.append(f'<a href="/training/{next_l["id"]}?mode={"fast" if fast else "normal"}"><button>Next →</button></a>')
        body=f'''<div class="panel pad tc-mission-hero"><div class="inline" style="justify-content:space-between;align-items:flex-start"><div><div class="muted">{html.escape(lesson["track"])} · Mission {idx+1}/{len(LESSONS)}</div><h2>{html.escape(lesson["title"])}</h2><div>{html.escape(lesson["objective"])}</div></div><div><span class="badge">{lesson["xp"]} XP</span> <span class="badge">~{lesson["minutes"]} min</span></div></div>
<div class="tc-progress" style="margin-top:14px"><span style="width:{round((idx+1)*100/len(LESSONS))}%"></span></div>
<div class="inline" style="margin-top:14px"><a href="/training/{lesson_id}?mode={"normal" if fast else "fast"}"><button>{"Normal mode" if fast else "Fast mode"}</button></a><span class="muted">{"Fast mode: objective only." if fast else "Normal mode: explanation + guided steps."}</span></div></div>
{explanation}
<div class="panel pad"><h3>{"Speed objective" if fast else "Practice in Tikcentral"}</h3><div class="muted" style="margin-bottom:10px">Open the real feature in another view, perform the mission, then return here to record your progress.</div>
<div class="inline"><a href="{lesson["route"]}"><button class="primary">{html.escape(lesson["cta"])}</button></a>
<form method="post" action="/training/{lesson_id}/status"><input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="status" value="completed"><button class="primary">✓ Complete mission</button></form>
<form method="post" action="/training/{lesson_id}/status"><input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="status" value="skipped"><button>I already know this · Skip</button></form></div></div>
<div class="panel pad"><div class="inline" style="justify-content:space-between">{"".join(nav)}<span class="muted">Current: {html.escape(STATUS_LABELS.get(st,st))}</span></div></div>'''
        return page_func(f"Training · {lesson['title']}",body,user,"training")

    @app.post("/training/{lesson_id}/status")
    async def lesson_status(lesson_id:str,request:Request):
        user=core.require_web_role(request,"viewer")
        if not user:return RedirectResponse("/login",303)
        lesson=_lesson(lesson_id)
        if not lesson:return RedirectResponse("/training",303)
        data=await core.form_data(request);core.require_csrf(request,data.get("csrf",""))
        status=str(data.get("status","")).strip()
        if status not in {"completed","skipped","in_progress"}:
            return RedirectResponse(f"/training/{lesson_id}",303)
        uid=_user_id(user)
        _set_status(uid,lesson_id,status)
        progress=_progress(uid)
        next_l=next((x for x in LESSONS[LESSONS.index(lesson)+1:] if progress.get(x["id"],{}).get("status") not in {"completed","skipped"}),None)
        return RedirectResponse(f"/training/{next_l['id']}" if next_l else "/training",303)

    @app.post("/training/track/{track_slug}/skip")
    async def skip_track(track_slug:str,request:Request):
        user=core.require_web_role(request,"viewer")
        if not user:return RedirectResponse("/login",303)
        data=await core.form_data(request);core.require_csrf(request,data.get("csrf",""))
        track=next((name for name in dict.fromkeys(x["track"] for x in LESSONS) if _track_slug(name)==track_slug),None)
        if not track:return RedirectResponse("/training",303)
        progress=_progress(_user_id(user))
        for lesson in (x for x in LESSONS if x["track"]==track):
            if progress.get(lesson["id"],{}).get("status") not in {"completed","skipped"}:
                _set_status(_user_id(user),lesson["id"],"skipped")
        return RedirectResponse("/training",303)

    @app.post("/training/reset")
    async def reset_training(request:Request):
        user=core.require_web_role(request,"viewer")
        if not user:return RedirectResponse("/login",303)
        data=await core.form_data(request);core.require_csrf(request,data.get("csrf",""))
        with core.db() as conn:
            conn.execute("DELETE FROM user_training_progress WHERE user_id=?",(_user_id(user),))
        return RedirectResponse("/training",303)
