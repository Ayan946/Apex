import argparse
import requests
from apex.discovery import discover_surface
from apex.checks import run_all_checks, HEADERS

BANNER = """
\033[35m
  _    ____  _______  __
   / \\  |  _ \\| ____\\ \\/ /
  / _ \\ | |_) |  _|  \\  / 
 / ___ \\|  __/| |___ /  \\ 
/_/   \\_\\_|   |_____/_/\\_\\
\033[0m
\033[90m        API Security Scanner\033[0m
"""


def parse_args():
    p = argparse.ArgumentParser(prog="apex", description="OWASP API Top 10 Scanner")
    p.add_argument("-t", "--target", required=True, help="Target API base URL")
    p.add_argument("-o", "--output", help="Save output to file")
    return p.parse_args()


def print_summary(findings, output_file=None):
    sev_count = {}
    for f in findings:
        sev_count[f["severity"]] = sev_count.get(f["severity"], 0) + 1

    lines = ["", "[INF] ─────────────────────────────────────", "[INF] Scan completed"]
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        lines.append(f"[INF] {sev}: {sev_count.get(sev, 0)}")
    lines.append(f"[INF] Total findings: {len(findings)}")
    lines.append("[INF] ─────────────────────────────────────")

    for line in lines:
        print(line)
        if output_file:
            output_file.write(line + "\n")


def main():
    print(BANNER)
    args = parse_args()
    target = args.target if args.target.startswith("http") else f"http://{args.target}"

    output_file = open(args.output, "w") if args.output else None
    session = requests.Session()
    session.headers.update(HEADERS)

    try:
        print(f"[INF] Target: {target}\n")
        surface = discover_surface(session, target, output_file)
        print()
        findings = run_all_checks(session, target, surface["endpoints"], output_file)
        print_summary(findings, output_file)
    finally:
        if output_file:
            print(f"\n[INF] Output saved to {args.output}")
            output_file.close()


if __name__ == "__main__":
    main()
