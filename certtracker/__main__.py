"""Command line: python -m certtracker {scheduler,run-daily,scan,send-digest,test-email}"""
import argparse
import sys

from . import create_app, jobs, notify


def main(argv=None):
    parser = argparse.ArgumentParser(prog="certtracker")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("scheduler", help="run the daily job forever at DAILY_RUN_TIME")
    sub.add_parser("run-daily", help="run the daily job once now")
    sub.add_parser("scan", help="scan all endpoints once, no email")
    digest = sub.add_parser("send-digest", help="build and send the digest now")
    digest.add_argument("--weekly", action="store_true", help="send the weekly summary even if nothing is wrong")
    sub.add_parser("test-email", help="send a test email to DIGEST_TO")
    args = parser.parse_args(argv)

    app = create_app()
    factory, config = app.session_factory, app.config
    if args.command == "scheduler":
        jobs.scheduler_loop(factory, config)
    elif args.command == "run-daily":
        run = jobs.run_daily(factory, config)
        print(run.summary)
        return 0 if run.ok else 1
    elif args.command == "scan":
        print(jobs.scan_all(factory(), config))
    elif args.command == "send-digest":
        print(jobs.send_digest(factory(), config, force_weekly=True if args.weekly else None))
    elif args.command == "test-email":
        notify.send_email(config, "[Cert Tracker] Test email", "This is a test from Cert Tracker.")
        print("sent")
    return 0


if __name__ == "__main__":
    sys.exit(main())
