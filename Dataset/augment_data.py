import json
import random
import copy
import uuid

INPUT_FILE = "../cli/master_dataset.json"
OUTPUT_FILE = "master_dataset_augmented.json"
TARGET_COUNT = 200

# Common variable name replacements to create diverse code snippets
REPLACEMENTS = [
    ("prompt", ["user_query", "input_text", "user_prompt", "q_string"]),
    ("messages", ["chat_history", "history", "msg_list", "dialogue"]),
    ("openai", ["llm_client", "ai_client", "model_api", "gpt_client"]),
    ("response", ["llm_res", "completion", "output_data", "result"]),
    ("systemPrompt", ["sys_instruction", "base_prompt", "guardrail_msg"]),
    ("client", ["db_conn", "connection", "pg_client", "database"]),
]


def augment_code(code_string):
    """Slightly mutates code by swapping variable names and adding spacing."""
    mutated = code_string
    # Randomly replace 1 or 2 variable names
    for target, options in random.sample(REPLACEMENTS, k=random.randint(1, 3)):
        mutated = mutated.replace(target, random.choice(options))

    # Randomly alter spacing to change character n-grams
    if random.random() > 0.5:
        mutated = mutated.replace(" = ", "=")
    if random.random() > 0.5:
        mutated = mutated.replace(", ", ",")

    return mutated


def main():
    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        dataset = json.load(f)

    original_count = len(dataset)
    print(f"[*] Loaded {original_count} original examples.")

    augmented_dataset = list(dataset)

    # Keep augmenting until we hit the target
    while len(augmented_dataset) < TARGET_COUNT:
        # Pick a random entry to clone and mutate
        base_entry = random.choice(dataset)
        new_entry = copy.deepcopy(base_entry)

        # Give it a unique ID
        new_entry["id"] = f"{base_entry['id']}_aug_{uuid.uuid4().hex[:6]}"

        # Mutate the code slightly
        new_entry["code"] = augment_code(new_entry["code"])

        augmented_dataset.append(new_entry)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(augmented_dataset, f, indent=2, ensure_ascii=False)

    print(f"[+] Augmentation complete! Generated {len(augmented_dataset)} total examples.")
    print(f"[+] Saved to {OUTPUT_FILE}. You can now run trainModel.py on this file.")


if __name__ == "__main__":
    main()