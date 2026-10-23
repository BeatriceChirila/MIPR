"""
trainModel.py - teaches the scanner to spot risky lines of code.

How to run:
    python cli\trainModel.py cli\master_dataset_clean.json --out model.joblib

What happens:
  1. Load the dataset and cleanup
  2. Turn every line of code into one training example (3-line window). Each example gets a label: an OWASP category
     (LLM01 ... LLM10) if the line is risky, or SAFE if it is not.
  3. Check how good the model is with four tests.
  4. Train the final model on ALL the data and save it.

The four tests:
  Test 1 = separate files by file_ids. If we have a file & a slightly modified copy of it,
            they have different ids => they may be one in testing one in training. => higher scores :)

  Test 2 = files grouped by root source name (original_files) => all similar files stay in the same batch => 
            test pile is brand new.

  Test 3 = Learn from the real files, test the synthetic
  Test 4 =vLearn from the synthetic files, test the real

How to read the results:
  precision - of the lines it flagged, how many were really risky
  recall - of the really risky lines, how many it found
  right category  when it found a risky line, did it name the correct OWASP category
"""
import argparse
import hashlib
import json
from collections import Counter

import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, f1_score, precision_recall_fscore_support
from sklearn.model_selection import StratifiedGroupKFold, cross_val_predict
from sklearn.pipeline import FeatureUnion, Pipeline

from MLDetector import CONTEXT, lang_of, make_windows

SAFE_LABELS = {"none", "safe", ""}


def load_records(path):
    with open(path, encoding="utf-8") as f:
        text = f.read().strip()
    if text.startswith("["):
        return json.loads(text)
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def cleanup(records):
    seen, files = set(), []
    notes = Counter()
    for r in records:
        file_id = hashlib.md5(r["code"].encode("utf-8")).hexdigest()
        if file_id in seen:
            notes["duplicate files removed"] += 1
            continue
        seen.add(file_id)

        cats = r.get("categories") or []
        category = str(cats[0]) if cats else "SAFE"
        if category.strip().lower() in SAFE_LABELS:
            category, risky_lines = "SAFE", []
        else:
            risky_lines = list(r.get("vulnerable_lines") or [])
            if not risky_lines:
                notes["files dropped (category but no marked lines)"] += 1
                continue

        files.append({
            "code": r["code"],
            "category": category,
            "risky_lines": set(risky_lines),
            "language": lang_of(r.get("language", r.get("file_path", "python"))),
            "kind": "real" if r.get("origin") == "real" else "synthetic",
            "original_file": r.get("file_path", r.get("id", "?")),
            "file_id": file_id,
        })
    return files, notes


def make_examples(files):
    """chops input files down into 3-sliding window pieces."""
    texts, labels, file_ids, original_files, kinds, names = [], [], [], [], [], []
    for f in files:
        for line_number, text in make_windows(f["code"], f["language"]):
            texts.append(text)
            labels.append(f["category"] if line_number in f["risky_lines"] else "SAFE")
            file_ids.append(f["file_id"])
            original_files.append(f["original_file"])
            kinds.append(f["kind"])
            names.append(f'{f["original_file"]}:{line_number}')
    return (np.array(texts, dtype=object), np.array(labels), np.array(file_ids),
            np.array(original_files), np.array(kinds), np.array(names))


def build_model():
    """uses logistic regression to decide which label fits best."""
    features = FeatureUnion([
        ("characters", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5),
                                       lowercase=True, sublinear_tf=True)),
        ("words", TfidfVectorizer(token_pattern=r"[A-Za-z_][A-Za-z0-9_]*|[^\sA-Za-z0-9_]",
                                  ngram_range=(1, 3), lowercase=True, sublinear_tf=True)),
    ])
    return Pipeline([("features", features),
                     ("classifier", LogisticRegression(C=10, max_iter=3000, class_weight="balanced"))])


def decide(probabilities, classes, threshold):
    """Turn probabilities into a final answer per line.
    If the model is at least `threshold` sure the line is NOT safe, flag it and name the
    most likely category. Otherwise SAFE."""
    safe = classes.index("SAFE")
    how_risky = 1.0 - probabilities[:, safe]
    risky_only = probabilities.copy()
    risky_only[:, safe] = -1.0                       # ignore SAFE when picking the category
    best_category = np.array(classes)[risky_only.argmax(1)]
    return np.where(how_risky >= threshold, best_category, "SAFE")


def show_scores(title, truth, answer):
    risky = truth != "SAFE"
    flagged = answer != "SAFE"
    precision, recall, _, _ = precision_recall_fscore_support(
        risky, flagged, average="binary", zero_division=0)
    right_category = (answer[risky] == truth[risky]).mean() if risky.any() else float("nan")
    overall = f1_score(truth, answer, average="macro", zero_division=0)
    print(f"{title:<40} precision {precision:.2f} | recall {recall:.2f} | "
          f"right category {right_category:.2f} | overall F1 {overall:.2f}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dataset")
    ap.add_argument("--out", default="model.joblib")
    ap.add_argument("--folds", type=int, default=5, help="how many parts to split the data into for the tests")
    ap.add_argument("--threshold", type=float, default=0.5,
                    help="how sure the model must be before flagging a line (0-1, higher = stricter)")
    args = ap.parse_args()

    files, notes = cleanup(load_records(args.dataset))
    texts, labels, file_ids, original_files, kinds, names = make_examples(files)
    classes = sorted(set(labels))

    print("About the data")
    print(f"  tidy-up: {dict(notes)}")
    print(f"  files: {len(files)} ({dict(Counter(f['kind'] for f in files))}), "
          f"languages: {dict(Counter(f['language'] for f in files))}")
    print(f"  files per category: {dict(Counter(f['category'] for f in files))}")
    print(f"  original files (before copies): {len(set(original_files))}")
    print(f"  lines (examples): {len(labels)}, per label: {dict(Counter(map(str, labels)))}\n")

    splitter = StratifiedGroupKFold(n_splits=args.folds, shuffle=True, random_state=42)

    # ---- Test 1 ----
    probs_1 = cross_val_predict(build_model(), texts, labels, cv=splitter,
                                groups=file_ids, method="predict_proba")
    answer_1 = decide(probs_1, classes, args.threshold)

    print("Test 1 details, per category")
    print(classification_report(labels, answer_1, zero_division=0))

    print(f"RESULTS (threshold {args.threshold})")
    show_scores("Test 1: hide files (easier)", labels, answer_1)

    # ---- Test 2 ----
    if len(set(original_files)) >= args.folds:
        probs_2 = cross_val_predict(build_model(), texts, labels, cv=splitter,
                                    groups=original_files, method="predict_proba")
        show_scores("Test 2: hide whole originals (harder)", labels,
                    decide(probs_2, classes, args.threshold))

    # ---- Tests 3 and 4 ----
    for learn_from, judge, title in (("real", "synthetic", "Test 3: learn real, judge synthetic"),
                                     ("synthetic", "real", "Test 4: learn synthetic, judge real")):
        learn, test = kinds == learn_from, kinds == judge
        if learn.sum() == 0 or test.sum() == 0:
            continue
        model = build_model().fit(texts[learn], labels[learn])
        probs = model.predict_proba(texts[test])
        show_scores(title, labels[test], decide(probs, [str(c) for c in model.classes_], args.threshold))

    # ---- mistakes ----
    missed = np.where((answer_1 != labels) & (labels != "SAFE"))[0]
    print("\nMistakes from Test 1 (risky missed or put in the wrong category)")
    rng = np.random.default_rng(0)
    for k in rng.choice(missed, size=min(5, len(missed)), replace=False):
        print(f"{names[k]} | real label: {labels[k]} | model said: {answer_1[k]}\n{texts[k]}\n---")

    # ---- final model: learn from everything and save ----
    final = build_model().fit(texts, labels)
    joblib.dump(final, args.out)
    with open(args.out + ".json", "w", encoding="utf-8") as fh:
        json.dump({"threshold": args.threshold, "context": CONTEXT,
                   "classes": [str(c) for c in final.classes_]}, fh, indent=2)
    print(f"\nSaved the model to {args.out} (the threshold is stored in {args.out}.json)")


if __name__ == "__main__":
    main()