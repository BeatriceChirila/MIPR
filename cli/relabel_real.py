"""
Refine dataset by filtering out false positives from the real examples.
It removes trivial lines, boilerplate aso
Exports clean data to json file (dataset clean)
"""
import argparse
import csv
import json
import re
from collections import Counter, defaultdict

from MLDetector import lang_of, strip_comments

SAFE_LABELS = {"none", "safe", ""}
TRIVIAL = re.compile(r"""^(import\s|from\s+\S+\s+import\s|[\)\]\}\(\[\{,:;'"`]*$)""")


def norm(line):
    return re.sub(r"\s+", " ", line.strip())


def category_of(r):
    cats = r.get("categories") or []
    c = str(cats[0]) if cats else "SAFE"
    return "SAFE" if c.strip().lower() in SAFE_LABELS else c


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dataset")
    ap.add_argument("--out", default="master_dataset_clean.json")
    ap.add_argument("--review", default="relabel_review.csv")
    args = ap.parse_args()

    with open(args.dataset, encoding="utf-8") as fh:
        records = json.load(fh)

    # normalised text of every line, and which categories flag it
    texts = []
    flagged_in = defaultdict(set)
    for r in records:
        lines = strip_comments(r["code"], lang_of(r.get("language", r.get("file_path", "python")))).split("\n")
        texts.append(lines)
        cat = category_of(r)
        if cat == "SAFE":
            continue
        for i in r.get("vulnerable_lines") or []:
            if 1 <= i <= len(lines) and norm(lines[i - 1]):
                flagged_in[norm(lines[i - 1])].add(cat)

    stats = Counter()
    per_cat_before, per_cat_after = Counter(), Counter()
    out, review = [], []
    for r, lines in zip(records, texts):
        cat = category_of(r)
        if r.get("origin") != "real" or cat == "SAFE":
            out.append(r)
            continue
        keep = []
        for i in r.get("vulnerable_lines") or []:
            stats["real positives before"] += 1
            per_cat_before[cat] += 1
            t = norm(lines[i - 1]) if 1 <= i <= len(lines) else ""
            if not t or TRIVIAL.match(t):
                stats["removed: trivial"] += 1
            elif len(flagged_in[t]) > 1:
                stats["removed: shared across categories"] += 1
            else:
                keep.append(i)
                per_cat_after[cat] += 1
                review.append((cat, r.get("file_path", r.get("id")), i, t[:140]))
        if not keep:
            stats["real files dropped (no positive line left)"] += 1
            continue
        r = dict(r, vulnerable_lines=keep, labels_tightened=True)
        out.append(r)
        stats["real positives after"] += len(keep)

    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2, ensure_ascii=False)
    with open(args.review, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["category", "file", "line", "code"])
        w.writerows(sorted(review))

    print(f"Records in: {len(records)} -> out: {len(out)}")
    for k, v in stats.items():
        print(f"  {k}: {v}")
    print("Positive lines per category (before -> after):")
    for c in sorted(per_cat_before):
        print(f"  {c}: {per_cat_before[c]} -> {per_cat_after[c]}")
    print(f"[+] Cleaned dataset: {args.out} | review file: {args.review}")


if __name__ == "__main__":
    main()