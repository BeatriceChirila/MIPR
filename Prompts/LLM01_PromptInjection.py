import json
from datasets import load_dataset

# 1. Încarcă split-ul de test (are 116 exemple - perfect pentru cerința de 100-200)
dataset = load_dataset("deepset/prompt-injections", split="test")

formatted_data = []

for idx, item in enumerate(dataset):
    text_content = item["text"]
    is_injection = item["label"] == 1

    # Construim exemplul structurat
    example = {
        "id": idx + 1,
        "input_text": text_content,
        "is_vulnerable": bool(is_injection),
        # Mapăm pe categoria corespunzătoare din proiectul tău
        "category": "LLM01" if is_injection else "None",
        "severity": "High" if is_injection else "None",
        "explanation": (
            "Prompt injection attack detected attempting to override system behavior."
            if is_injection
            else "Standard safe user input."
        ),
        "fix": (
            "Sanitize input and enforce strict separation between instructions and user inputs."
            if is_injection
            else "None"
        ),
    }
    formatted_data.append(example)

# 2. Salvează local ca JSON pentru laborator
with open("LLM01_PromptInjection.json", "w", encoding="utf-8") as f:
    json.dump(formatted_data, f, indent=2, ensure_ascii=False)

print(f"Salvat cu succes: {len(formatted_data)} exemple!")