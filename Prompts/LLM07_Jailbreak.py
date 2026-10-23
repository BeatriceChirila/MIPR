import json
from datasets import load_dataset

# Folosim un dataset curat și stabil pentru atacuri de tip Jailbreak (LLM07)
# Acest dataset are o singură partiție ('train')
dataset = load_dataset("rubend18/ChatGPT-Jailbreak-Prompts", split="train")

formatted_data = []

# Extragem primele 50 de exemple pentru a menține setul de date mic
for idx, item in enumerate(dataset.select(range(50))):
    # Detectăm dinamic numele coloanei care conține textul
    # (în caz că e 'prompt', 'text' sau altceva)
    text_col = "prompt" if "prompt" in item else "text" if "text" in item else list(item.keys())[0]
    text_content = item[text_col]

    # Toate intrările din acest dataset sunt atacuri de tip jailbreak
    example = {
        "file": "system_prompt_manager.py",
        "line": idx + 1,
        "category": "LLM07",
        "severity": "High",
        "explanation": "Jailbreak attempt detected trying to leak system prompts or bypass filters.",
        "fix": "Implement input guardrails and isolate system prompts from user context.",
        "payload": text_content
    }
    formatted_data.append(example)

# Salvăm fișierul JSON
output_file = "LLM07_SystemPromptLeakage.json"
with open(output_file, "w", encoding="utf-8") as f:
    json.dump(formatted_data, f, indent=2, ensure_ascii=False)

print(f"Salvată cu succes! {len(formatted_data)} exemple pentru LLM07 au fost generate în {output_file}.")