import os
import json

# Point this to your damn-vulnerable-llm-agent-main or llms_LLMGoat folder
repo_root = "E:\\MIPR\\Dataset\\damn-vulnerable-llm-agent-main"
repo_name = os.path.basename(repo_root)

output_file = "../cli/master_dataset.json"

if os.path.exists(output_file):
    with open(output_file, "r", encoding="utf-8") as f:
        try:
            output_dataset = json.load(f)
            print(f"[*] Loaded {len(output_dataset)} existing entries from {output_file}")
        except json.JSONDecodeError:
            print(f"[!] Warning: {output_file} is empty or corrupted. Starting fresh.")
            output_dataset = []
else:
    output_dataset = []

FOLDER_TO_CATEGORY = {
    "LLM01": ("LLM01", "high", "User input or external context passed into LLM prompt without sanitization.", "Use strict prompt templates and input guardrails."),
    "LLM02": ("LLM02", "critical", "Sensitive information or secrets exposed to the LLM pipeline.", "Remove secrets/PII from context and use environment variables."),
    "LLM03": ("LLM03", "high", "Unverified model handler or untrusted supply chain component loaded.", "Pin model versions and verify package/model integrity."),
    "LLM04": ("LLM04", "high", "Training or RAG data loaded from unvalidated external sources.", "Validate and sanitize all documents before embedding or training."),
    "LLM05": ("LLM05", "critical", "LLM output handled unsafely (passed to SQL, eval, shell, or raw HTML).", "Parameterize queries and never pass raw LLM output to execution sinks."),
    "LLM06": ("LLM06", "high", "LLM agent or service granted excessive permissions without human approval.", "Scope tool permissions strictly and require human-in-the-loop for mutations."),
    "LLM07": ("LLM07", "high", "Confidential business logic or credentials embedded inside the system prompt.", "Move secrets and access control logic out of system prompts into backend code."),
    "LLM08": ("LLM08", "medium", "Vector store or embeddings queried without tenant isolation or access controls.", "Enforce user/tenant metadata filtering on vector similarity searches."),
    "LLM09": ("LLM09", "medium", "LLM output returned without factual verification or grounding checks.", "Implement RAG grounding scores and output validation."),
    "LLM10": ("LLM10", "medium", "LLM API call missing token limits, rate limiting, or timeout controls.", "Add max_tokens, request timeouts, and rate-limiting middleware.")
}

CATEGORY_MAP = {
    "llm01": "LLM01", "llm1": "LLM01",
    "llm02": "LLM02", "llm2": "LLM02",
    "llm03": "LLM03", "llm3": "LLM03",
    "llm04": "LLM04", "llm4": "LLM04",
    "llm05": "LLM05", "llm5": "LLM05",
    "llm06": "LLM06", "llm6": "LLM06",
    "llm07": "LLM07", "llm7": "LLM07",
    "llm08": "LLM08", "llm8": "LLM08",
    "llm09": "LLM09", "llm9": "LLM09",
    "llm10": "LLM10"
}

# Explicitly map the damn-vulnerable-llm-agent files to their actual OWASP vulnerabilities
EXPLICIT_FILES = {
    "damn-vulnerable-llm-agent-main/main.py": "LLM01",   # Prompt Injection
    "damn-vulnerable-llm-agent-main/tools.py": "LLM06",  # Excessive Agency (unrestricted DB tool)
    "damn-vulnerable-llm-agent-main/transaction_db.py": "LLM02" # Sensitive Info (Fake PII/Passwords)
}
# Expanded keywords to catch LangChain, TS, and Vercel AI SDK patterns
RISKY_KEYWORDS = [
    "prompt", "ollama", "generate", "chat", "embed", "execute", "eval(",
    "os.system", "subprocess", "secret", "password", "api_key", "rogue",
    "useChat", "ChatOpenAI", "createChatCompletion", "LangChainStream",
    "SystemMessage", "HumanMessage", "SQLDatabaseChain"
]

TARGET_EXTENSIONS = (".py", ".ts", ".js", ".tsx", ".jsx")

counter = len(output_dataset) + 1
new_entries_count = 0

for root, dirs, files in os.walk(repo_root):
    if any(skip in root for skip in ["__pycache__", ".locks", "models--", ".git", "node_modules"]):
        continue

    for file in files:
        if file.endswith(TARGET_EXTENSIONS) and file != "__init__.py":
            full_path = os.path.join(root, file)
            rel_path = os.path.relpath(full_path, repo_root).replace("\\", "/")

            # Infer language and framework
            language = "typescript" if file.endswith((".ts", ".tsx")) else "javascript" if file.endswith(
                (".js", ".jsx")) else "python"
            framework = "langchain / vercel-ai" if language in ["typescript", "javascript"] else "langchain / python"

            # Default to None
            cat_info = ("None", "low", "Safe infrastructure or standard application code.", "No fix required.")

            # 1. First, check if it's one of the explicitly mapped files
            matched_cat_id = None
            for explicit_path, mapped_cat in EXPLICIT_FILES.items():
                if explicit_path in full_path.replace("\\", "/"):
                    matched_cat_id = mapped_cat
                    break

            # 2. If not explicit, check folder names (handling llm1 vs llm01)
            if not matched_cat_id:
                for key_variant, mapped_cat in CATEGORY_MAP.items():
                    # Look for "/llm1/" or "\\llm1\\" in the path to avoid matching random words
                    if f"/{key_variant}/" in rel_path.lower() or f"\\{key_variant}\\" in rel_path.lower() or rel_path.lower().startswith(
                            f"{key_variant}/"):
                        matched_cat_id = mapped_cat
                        break

            # 3. Apply the matched category info
            if matched_cat_id and matched_cat_id in FOLDER_TO_CATEGORY:
                cat_info = FOLDER_TO_CATEGORY[matched_cat_id]

            cat_id, severity, explanation, fix = cat_info
            try:
                with open(full_path, "r", encoding="utf-8") as f:
                    lines = f.readlines()

                vuln_lines = []
                if cat_id != "None":
                    for idx, line in enumerate(lines, start=1):
                        if any(kw.lower() in line.lower() for kw in RISKY_KEYWORDS):
                            vuln_lines.append(idx)

                entry = {
                    "id": f"{repo_name}_{cat_id.lower()}_{counter:04d}",
                    "language": language,
                    "framework": framework,
                    "file_path": rel_path,
                    "code": "".join(lines),
                    "vulnerable_lines": vuln_lines,
                    "categories": [cat_id],
                    "severity": severity,
                    "explanation": explanation,
                    "suggested_fix": fix,
                    "origin": "real",
                    "source_url": f"local://{repo_name}/{rel_path}"
                }

                if not any(e.get("file_path") == rel_path and e.get("source_url") == entry["source_url"] for e in
                           output_dataset):
                    output_dataset.append(entry)
                    counter += 1
                    new_entries_count += 1

            except Exception as e:
                print(f"Skipping {rel_path}: {e}")

with open(output_file, "w", encoding="utf-8") as out_f:
    json.dump(output_dataset, out_f, indent=2, ensure_ascii=False)

print(
    f"[+] Added {new_entries_count} new files. 'master_dataset.json' now contains {len(output_dataset)} total entries!")