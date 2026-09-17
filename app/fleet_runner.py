import argparse

from app import errors
from app import fleet
from app import guardian
from app import migrations
from app import scheduler


def _best_effort(label, fn):
    try:
        return fn(), ""
    except Exception as exc:
        return None, f"{label} failed: {errors.short(exc)}"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["scheduled", "backup", "analysis", "guardian", "operations"])
    args = parser.parse_args()
    migrations.migrate()

    if args.action == "scheduled":
        # Access is the critical path and always runs first. Everything after it
        # is optional/best-effort and cannot invalidate a completed access check.
        access = guardian.guardian_tick()
        _, scheduler_error = _best_effort("operations scheduler", scheduler.scheduled_tick)
        backup_job, backup_error = _best_effort("fleet backup scheduler", fleet.scheduled_tick)
        print(f"guardian checked: {len(access)} router(s)")
        print(scheduler_error or "operations scheduler: completed")
        print(backup_error or (f"scheduled backup job: {backup_job}" if backup_job else "no fleet backup due"))
    elif args.action == "backup":
        print(f"backup job: {fleet.run_backup_job('cli')}")
    elif args.action == "analysis":
        print(f"analysis job: {fleet.run_analysis_job('cli')}")
    elif args.action == "operations":
        _, scheduler_error = _best_effort("operations scheduler", scheduler.scheduled_tick)
        print(scheduler_error or "operations scheduler: completed")
    else:
        print(f"guardian checked: {len(guardian.guardian_tick())} router(s)")


if __name__ == "__main__":
    main()
