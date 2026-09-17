import argparse

from app import fleet
from app import guardian
from app import migrations
from app import operations
from app import scheduler


def main():
    p = argparse.ArgumentParser()
    p.add_argument("action", choices=["scheduled", "backup", "analysis", "guardian", "operations"])
    args = p.parse_args()
    migrations.migrate()
    fleet.ensure_schema()
    guardian.ensure_schema()
    operations.ensure_schema()
    if args.action == "scheduled":
        access = guardian.guardian_tick()
        scheduler.scheduled_tick()
        job = fleet.scheduled_tick()
        print(f"guardian checked: {len(access)} router(s)")
        print("operations tick: completed")
        print(f"scheduled job: {job}" if job else "nothing due")
    elif args.action == "backup":
        print(f"backup job: {fleet.run_backup_job('cli')}")
    elif args.action == "analysis":
        print(f"analysis job: {fleet.run_analysis_job('cli')}")
    elif args.action == "operations":
        scheduler.scheduled_tick()
        print("operations tick: completed")
    else:
        print(f"guardian checked: {len(guardian.guardian_tick())} router(s)")


if __name__ == "__main__":
    main()
