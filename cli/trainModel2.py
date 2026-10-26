"""
trainModel2.py - Model 2: frozen UniXcoder embeddings + SVM / LogReg.

Run (from cli/):
    python trainModel2.py master_dataset_clean.json --out model2.joblib
"""
import argparse
import json
import warnings
from collections import Counter

import joblib
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedGroupKFold, cross_val_predict
from sklearn.pipeline import Pipeline
from sklearn.svm import SVC

from MLDetector import CONTEXT
from trainModel import cleanup, decide, load_records, make_examples, show_scores
from code_embedder import CodeEmbedder

warnings.filterwarnings("ignore", category=FutureWarning)


def build_model2(clf="svm", model_name="microsoft/unixcoder-base", C=10):
    if clf == "svm":
        head = SVC(kernel="rbf", C=C, gamma="scale", class_weight="balanced",
                   probability=True, random_state=42)
    else:
        head = LogisticRegression(C=C, max_iter=3000, class_weight="balanced")
    return Pipeline([("embed", CodeEmbedder(model_name=model_name)), ("classifier", head)])


def show_examples(names, texts, truth, answer, k=3):
    """TP / FN / FP samples for section 5.5.3.2 of the report."""
    rng = np.random.default_rng(0)
    groups = {
        "TRUE POSITIVE (correct category)": (truth != "SAFE") & (answer == truth),
        "FALSE NEGATIVE (risky line missed)": (truth != "SAFE") & (answer == "SAFE"),
        "WRONG CATEGORY": (truth != "SAFE") & (answer != "SAFE") & (answer != truth),
        "FALSE POSITIVE (safe line flagged)": (truth == "SAFE") & (answer != "SAFE"),
    }
    for title, mask in groups.items():
        idx = np.where(mask)[0]
        print(f"\n=== {title}: {len(idx)} total ===")
        for i in rng.choice(idx, size=min(k, len(idx)), replace=False):
            print(f"{names[i]} | real: {truth[i]} | model: {answer[i]}\n{texts[i]}\n---")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dataset")
    ap.add_argument("--out", default="model2.joblib")
    ap.add_argument("--folds", type=int, default=5)
    ap.add_argument("--threshold", type=float, default=0.5)
    ap.add_argument("--clf", choices=["svm", "logreg"], default="svm")
    ap.add_argument("--C", type=float, default=10)
    ap.add_argument("--encoder", default="microsoft/unixcoder-base")
    args = ap.parse_args()

    files, notes = cleanup(load_records(args.dataset))
    texts, labels, file_ids, original_files, kinds, names = make_examples(files)
    classes = sorted(set(labels))
    print(f"Model 2 [{args.encoder} + {args.clf}, C={args.C}] | lines: {len(labels)}, "
          f"per label: {dict(Counter(map(str, labels)))}\n")

    splitter = StratifiedGroupKFold(n_splits=args.folds, shuffle=True, random_state=42)
    saved = {}

    # ---- Test 1: group by file_id ----
    probs_1 = cross_val_predict(build_model2(args.clf, args.encoder, args.C), texts, labels,
                                cv=splitter, groups=file_ids, method="predict_proba")
    answer_1 = decide(probs_1, classes, args.threshold)
    show_scores("Test 1: hide files (easier)", labels, answer_1)
    saved["test1"] = answer_1

    # ---- Test 2: group by original file ----
    if len(set(original_files)) >= args.folds:
        probs_2 = cross_val_predict(build_model2(args.clf, args.encoder, args.C), texts, labels,
                                    cv=splitter, groups=original_files, method="predict_proba")
        answer_2 = decide(probs_2, classes, args.threshold)
        show_scores("Test 2: hide whole originals (harder)", labels, answer_2)
        saved["test2"] = answer_2

        print("\nTest 2, threshold sensitivity")
        for th in (0.5, 0.7, 0.8, 0.9, 0.95):
            show_scores(f"  Test 2 @ threshold {th}", labels, decide(probs_2, classes, th))
        print()

    # ---- Tests 3 / 4: cross-domain ----
    for learn_from, judge, title in (("real", "synthetic", "Test 3: learn real, judge synthetic"),
                                     ("synthetic", "real", "Test 4: learn synthetic, judge real")):
        learn, test = kinds == learn_from, kinds == judge
        if learn.sum() == 0 or test.sum() == 0:
            continue
        model = build_model2(args.clf, args.encoder, args.C).fit(texts[learn], labels[learn])
        probs = model.predict_proba(texts[test])
        mc = [str(c) for c in model.classes_]
        show_scores(title, labels[test], decide(probs, mc, args.threshold))

        risk = 1.0 - probs[:, mc.index("SAFE")]
        print(f"   risk max={risk.max():.2f}, p95={np.quantile(risk, 0.95):.2f}, "
              f"flagged@{args.threshold}={(risk >= args.threshold).sum()}/{len(risk)}")
        for th in (0.5, 0.7, 0.8, 0.9):
            show_scores(f"   @ threshold {th}", labels[test], decide(probs, mc, th))
        print()

    # ---- save predictions (so M1 and M2 can be compared on the same lines) + examples ----
    np.savez("preds_model2.npz", labels=labels, names=names, **saved)
    show_examples(names, texts, labels, answer_1)

    # ---- final model on everything, same artifacts as Model 1 ----
    final = build_model2(args.clf, args.encoder, args.C).fit(texts, labels)
    joblib.dump(final, args.out)
    with open(args.out + ".json", "w", encoding="utf-8") as fh:
        json.dump({"threshold": args.threshold, "context": CONTEXT,
                   "classes": [str(c) for c in final.classes_],
                   "encoder": args.encoder}, fh, indent=2)
    print(f"\nSaved Model 2 to {args.out}")


if __name__ == "__main__":
    main()