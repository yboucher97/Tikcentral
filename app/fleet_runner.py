import argparse

from app import fleet


def main():
    p = argparse.ArgumentParser()
    p.add_argument("action", choices=["scheduled", "backup", "analysis"])
    args = p.parse_args()
    fleet.ensure_schema()
    if args.action == "scheduled":
        job = fleet.scheduled_tick()
        print(f"scheduled job: {job}" if job else "nothing due")
    elif args.action == "backup":
        print(f"backup job: {fleet.run_backup_job('cli')}")
    else:
        print(f"analysis job: {fleet.run_analysis_job('cli')}")


if __name__ == "__main__":
    main()
