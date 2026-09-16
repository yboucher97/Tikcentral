import argparse

from app import fleet
from app import guardian


def main():
    p = argparse.ArgumentParser()
    p.add_argument("action", choices=["scheduled", "backup", "analysis", "guardian"])
    args = p.parse_args()
    fleet.ensure_schema()
    guardian.ensure_schema()
    if args.action == "scheduled":
        access = guardian.guardian_tick()
        job = fleet.scheduled_tick()
        print(f"guardian checked: {len(access)} router(s)")
        print(f"scheduled job: {job}" if job else "nothing due")
    elif args.action == "backup":
        print(f"backup job: {fleet.run_backup_job('cli')}")
    elif args.action == "analysis":
        print(f"analysis job: {fleet.run_analysis_job('cli')}")
    else:
        print(f"guardian checked: {len(guardian.guardian_tick())} router(s)")


if __name__ == "__main__":
    main()
