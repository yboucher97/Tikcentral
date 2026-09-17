import argparse

from app import fleet
from app import guardian
from app import migrations
from app import operations
from app import scheduler


def _best_effort(label, fn):
    try:
        return fn(), ""
    except Exception as exc:
        return None, f"{label} failed: {exc}"


def main():
    p = argparse.ArgumentParser()
    p.add_argument("action", choices=["scheduled", "backup", "analysis", "guardian", "operations"])
    args = p.parse_args()
    migrations.migrate()
    fleet.ensure_schema()
    guardian.ensure_schema()
    operations.ensure_schema()
    if args.action == "scheduled":
        # Guardian is the critical path and always runs first. Everything after
        # it is optional/best-effort and cannot invalidate a completed access check.
        access = guardian.guardian_tick()
        _, sched_error = _best_effort("optional scheduler", scheduler.scheduled_tick)
        job, fleet_error = _best_effort("legacy fleet scheduler", fleet.scheduled_tick)
        print(f"guardian checked: {len(access)} router(s)")
        print(sched_error or "optional scheduler: completed")
        print(fleet_error or (f"scheduled job: {job}" if job else "nothing due"))
    elif args.action == "backup":
        print(f"backup job: {fleet.run_backup_job('cli')}")
    elif args.action == "analysis":
        print(f"analysis job: {fleet.run_analysis_job('cli')}")
    elif args.action == "operations":
        result, error = _best_effort("optional scheduler", scheduler.scheduled_tick)
        print(error or "operations tick: completed")
    else:
        print(f"guardian checked: {len(guardian.guardian_tick())} router(s)")


if __name__ == "__main__":
    main()
