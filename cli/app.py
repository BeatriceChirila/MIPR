import argparse
import json
import time
import sys
from colorama import init, Fore, Style
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

FINDINGS = [
    {"file": "main.py", "line": 1, "category": "LLM02", "severity": "Critical",
     "explanation": "API key hard-coded in source code.", "fix": "Read it from an environment variable."},
    {"file": "main.py", "line": 2, "category": "LLM07", "severity": "High",
     "explanation": "Password stored inside the system prompt.", "fix": "Keep secrets out of prompts."},
    {"file": "agent.py", "line": 5, "category": "LLM01", "severity": "High",
     "explanation": "User input concatenated directly into the prompt.",
     "fix": "Send user input as a separate message and sanitize."},
    {"file": "agent.py", "line": 6, "category": "LLM10", "severity": "Medium",
     "explanation": "No max_tokens or rate limit on the model call.", "fix": "Add max_tokens and a timeout."},
    {"file": "utils.py", "line": 10, "category": "LLM05", "severity": "Critical",
     "explanation": "LLM output executed in a shell.", "fix": "Never execute model output directly."}
]


def simulate_scan(target_path):
    print(f"{Colors.BOLD}{Colors.BLUE}[*] Starting LLM Security Guardian scan on: {target_path}{Colors.ENDC}")
    for i in range(3):
        time.sleep(0.5)
        sys.stdout.write("..")
        sys.stdout.flush()
    print("\n")


def print_scorecard():
    print(f"{Colors.BOLD}--- COMPLIANCE SCORECARD ---{Colors.ENDC}")

    found_categories = {f['category']: 0 for f in FINDINGS}
    for f in FINDINGS:
        found_categories[f['category']] += 1

    for cat_id, cat_name in CATEGORIES.items():
        count = found_categories.get(cat_id, 0)
        if count > 0:
            print(f"{Colors.FAIL}[FAIL]{Colors.ENDC} {cat_id}: {cat_name} ({count} findings)")
        else:
            print(f"{Colors.GREEN}[PASS]{Colors.ENDC} {cat_id}: {cat_name}")
    print("\n")


def print_findings():
    print(f"{Colors.BOLD}--- ANALYSIS RESULTS ---{Colors.ENDC}")
    for f in FINDINGS:
        color = Colors.FAIL if f['severity'] == 'Critical' else Colors.HIGH if f['severity'] == 'High' else Colors.MEDIUM
        print(
            f"{Colors.BOLD}{f['file']}:{f['line']}{Colors.ENDC} | {color}{f['severity']}{Colors.ENDC} | {f['category']} {CATEGORIES[f['category']]}")
        print(f"    {Colors.BOLD}Issue:{Colors.ENDC} {f['explanation']}")
        print(f"    {Colors.BOLD}Fix:{Colors.ENDC}   {f['fix']}\n")


def export_json(output_path):
    with open(output_path, 'w') as f:
        json.dump(FINDINGS, f, indent=2)
    print(f"{Colors.GREEN}[+] Report successfully exported to {output_path}{Colors.ENDC}")


def main():
    parser = argparse.ArgumentParser(description="LLM Code Security Scanner")
    parser.add_argument("target", help="Path to the repository or directory to scan")
    parser.add_argument("--export", help="Export findings to a JSON file (e.g. report.json)", metavar="FILE")

    args = parser.parse_args()

    simulate_scan(args.target)
    print_scorecard()
    print_findings()

    if args.export:
        export_json(args.export)


if __name__ == "__main__":
    main()