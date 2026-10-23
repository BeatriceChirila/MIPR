import argparse
import json
import sys
from colorama import init, Fore, Style
from MLDetector import scan_repo
init()


class Colors:
    HEADER = Fore.MAGENTA
    BLUE = Fore.BLUE
    GREEN = Fore.GREEN
    MEDIUM = Fore.LIGHTBLACK_EX
    HIGH = Fore.LIGHTYELLOW_EX
    FAIL = Fore.RED
    ENDC = Style.RESET_ALL
    BOLD = Style.BRIGHT


CATEGORIES = {
    "LLM01": "Prompt injection",
    "LLM02": "Sensitive information disclosure",
    "LLM03": "Supply chain",
    "LLM04": "Data and model poisoning",
    "LLM05": "Improper output handling",
    "LLM06": "Excessive agency",
    "LLM07": "System prompt leakage",
    "LLM08": "Vector and embedding weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded consumption",
}


def print_scorecard(findings):
    print(f"{Colors.BOLD}--- COMPLIANCE SCORECARD ---{Colors.ENDC}")

    counts = {}
    for f in findings:
        counts[f['category']] = counts.get(f['category'], 0) + 1

    for cat_id, cat_name in CATEGORIES.items():
        n = counts.get(cat_id, 0)
        if n > 0:
            print(f"{Colors.FAIL}[FAIL]{Colors.ENDC} {cat_id}: {cat_name} ({n} findings)")
        else:
            print(f"{Colors.GREEN}[PASS]{Colors.ENDC} {cat_id}: {cat_name}")
    print("\n")


def print_findings(findings):
    print(f"{Colors.BOLD}--- ANALYSIS RESULTS ---{Colors.ENDC}")
    for f in findings:
        color = Colors.FAIL if f['severity'] == 'Critical' else Colors.HIGH if f['severity'] == 'High' else Colors.MEDIUM
        print(
            f"{Colors.BOLD}{f['file']}:{f['line']}{Colors.ENDC} | {color}{f['severity']}{Colors.ENDC} | {f['category']} {CATEGORIES[f['category']]}")
        print(f"    {Colors.BOLD}Issue:{Colors.ENDC} {f['explanation']}")
        print(f"    {Colors.BOLD}Fix:{Colors.ENDC}   {f['fix']}\n")


def export_json(findings, output_path):
    with open(output_path, 'w') as f:
        json.dump(findings, f, indent=2)
    print(f"{Colors.GREEN}[+] Report successfully exported to {output_path}{Colors.ENDC}")

def export_lcov(findings, output_path="lcov.info"):
    from collections import defaultdict
    file_map = defaultdict(set)
    for f in findings:
        file_map[f['file']].add(int(f['line']))

    with open(output_path, 'w') as out:
        for file_path, lines in file_map.items():
            out.write("TestName:\n")
            out.write(f"SourceFile:{file_path}\n")
            for line in sorted(lines):
                out.write(f"Data:{line},0\n") 
            out.write("end_of_record\n")
    print(f"{Colors.GREEN}[+] Coverage exported to {output_path}{Colors.ENDC}")

def main():
    parser = argparse.ArgumentParser(description="LLM Code Security Scanner")
    parser.add_argument("target", help="Path to the repository or directory to scan")
    parser.add_argument("--export", help="Export findings to a JSON file (e.g. report.json)", metavar="FILE")

    parser.add_argument("--model", default="model.joblib")
    parser.add_argument("--fail-on-critical", action="store_true", help="Exit with code 1 if any Critical finding exists (used by CI to block merges)")
    parser.add_argument("--lcov", help="Export as lcov.info", metavar="FILE")

    args = parser.parse_args()


    findings = scan_repo(args.target, model_path = args.model)

    print_scorecard(findings)
    print_findings(findings)

    if args.export:
        export_json(findings, args.export)

    if args.fail_on_critical and any(f["severity"] == "Critical" for f in findings):
        print(f"{Colors.FAIL}[!] Critical findings detected - failing the check.{Colors.ENDC}")
        sys.exit(1)

    if args.lcov:
        export_lcov(findings, args.lcov)


if __name__ == "__main__":
    main()