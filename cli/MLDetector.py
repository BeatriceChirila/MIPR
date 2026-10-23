"""
Scans a repository with the trained model and returns findings in the format used by app.py.

a line is reported when  1 - P(SAFE) >= threshold,
and its category is the most probable nonsafe class. The threshold is chosen during
training (stored in <model>.json next to the model) and can be overridden.
"""
import ast
import json
import os
import re

import joblib
import numpy as np

EXTENSIONS = (".py", ".ts", ".tsx", ".js", ".jsx")
SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build"}
CONTEXT = 1               # neighbouring lines on each side of the analysed line, creates a  3-line sliding window for better analysis
DEFAULT_THRESHOLD = 0.5   # used only if the model has no <model>.json metadata

# Words that give the answer away
HINT = re.compile(r"(vulnerab|insecure|unsafe|exploit|secure|safe|fix|bad|good|danger|risk|malicious|attack|inject)")

SEVERITY = {
    "LLM01": "High", "LLM02": "Critical", "LLM03": "Medium", "LLM04": "Medium",
    "LLM05": "Critical", "LLM06": "High", "LLM07": "High", "LLM08": "High",
    "LLM09": "Low", "LLM10": "Medium",
}
EXPLANATION = {
    "LLM01": "User input appears to be concatenated into the prompt without separation or sanitisation.",
    "LLM02": "Secrets or sensitive data may be exposed to the model or in responses.",
    "LLM03": "Unpinned or unverified model, plugin or dependency.",
    "LLM04": "Untrusted data may be used for training, fine-tuning or retrieval.",
    "LLM05": "LLM output appears to be passed to a dangerous sink (eval, shell, SQL, HTML).",
    "LLM06": "Agent/tool has broad permissions or no human approval step.",
    "LLM07": "System prompt appears to contain credentials or business logic.",
    "LLM08": "Vector store/RAG without access control or tenant isolation.",
    "LLM09": "Model output is used without verification.",
    "LLM10": "Missing token cap, timeout or rate limit on model calls.",
}
FIX = {
    "LLM01": "Send user input as a separate message and sanitise/validate it.",
    "LLM02": "Load secrets from environment variables and redact PII before sending.",
    "LLM03": "Pin versions/hashes and load models from verified sources.",
    "LLM04": "Validate and provenance-check all training/retrieval data.",
    "LLM05": "Never execute model output directly; validate and encode it first.",
    "LLM06": "Apply least privilege and require human approval for risky actions.",
    "LLM07": "Keep secrets and sensitive logic out of prompts.",
    "LLM08": "Add per-tenant access control and filtering to the vector store.",
    "LLM09": "Add verification/grounding and show uncertainty to users.",
    "LLM10": "Add max_tokens, timeouts and rate limiting.",
}


def lang_of(path_or_lang):
    """'python' for .py / 'python', anything else is treated as JS/TS."""
    s = str(path_or_lang).lower()
    return "python" if s.endswith(".py") or s == "python" else "typescript"


def _string_statement_lines(code):
    """Line numbers (1-indexed) of docstrings / bare string statements in Python code.

    These are documentation, not behaviour (e.g. a challenge description saying 'Vulnerability: ...'),
    so they are blanked out. Strings that are assigned or passed (SYSTEM_PROMPT = \"\"\"...\"\"\") are kept.
    """
    try:
        tree = ast.parse(code)
    except (SyntaxError, ValueError):
        return set()
    lines = set()
    for node in ast.walk(tree):
        if (isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)):
            lines.update(range(node.lineno, (node.end_lineno or node.lineno) + 1))
    return lines


def strip_comments(code, lang="python"):
    marker = "#" if lang == "python" else "//"
    doc_lines = _string_statement_lines(code) if lang == "python" else set()
    out, in_block = [], False
    for lineno, line in enumerate(code.split("\n"), start=1):
        if lineno in doc_lines:
            out.append("")
            continue
        s = line.strip()
        if lang != "python":
            if in_block:
                out.append("")
                if "*/" in s:
                    in_block = False
                continue
            if s.startswith("/*"):
                out.append("")
                if "*/" not in s:
                    in_block = True
                continue
        if s.startswith(marker):
            out.append("")
            continue
        m = re.search(r"\s" + re.escape(marker) + r"\s.*$", line)  # trailing comment with a giveaway word
        if m and HINT.search(m.group(0)):
            line = line[:m.start()]
        out.append(line)
    return "\n".join(out)


def make_windows(code, lang="python"):
    """Yield (line_number_1_indexed, window_text) this is the data that actually gets fed into the model"""
    lines = strip_comments(code, lang).split("\n")
    for i, line in enumerate(lines):
        if not line.strip():
            continue
        yield i + 1, "\n".join(lines[max(0, i - CONTEXT): i + CONTEXT + 1])


def _iter_files(root):
    #Recursively search the dir 
    if os.path.isfile(root):
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if name.endswith(EXTENSIONS):
                yield os.path.join(dirpath, name)


def load_threshold(model_path):
    # Loads the f1optimal probability threshold saved during training
    meta_path = model_path + ".json"
    if os.path.exists(meta_path):
        with open(meta_path, encoding="utf-8") as fh:
            return float(json.load(fh).get("threshold", DEFAULT_THRESHOLD))
    return DEFAULT_THRESHOLD

# Loads the .joblib model, extracts sliding windows, calculates porbabilities
# If a window's non-safe probability exceeds the threshold, it constructs a finding dictionary 
# containing the file, line number, category, severity, and suggested fix, returning a sorted list of all results.
def scan_repo(target, model_path="model.joblib", threshold=None):
    model = joblib.load(model_path)
    classes = [str(c) for c in model.classes_]
    safe_idx = classes.index("SAFE")
    if threshold is None:
        threshold = load_threshold(model_path)
    base = target if os.path.isdir(target) else os.path.dirname(target) or "."

    windows, meta = [], []
    for path in _iter_files(target):
        try:
            with open(path, encoding="utf-8", errors="ignore") as fh:
                code = fh.read()
        except OSError:
            continue
        rel = os.path.relpath(path, base)
        for lineno, window in make_windows(code, lang_of(path)):
            windows.append(window)
            meta.append((rel, lineno))

    if not windows:
        return []

    probas = model.predict_proba(windows)
    vuln_score = 1.0 - probas[:, safe_idx]
    non_safe = probas.copy()
    non_safe[:, safe_idx] = -1.0

    findings = []
    for (file, line), score, p in zip(meta, vuln_score, non_safe):
        if score < threshold:
            continue
        label = classes[int(p.argmax())]
        findings.append({
            "file": file, "line": line, "category": label,
            "severity": SEVERITY.get(label, "Medium"),
            "explanation": EXPLANATION.get(label, ""),
            "fix": FIX.get(label, ""),
            "confidence": round(float(score), 2),
        })
    findings.sort(key=lambda f: (f["file"], f["line"]))
    return findings