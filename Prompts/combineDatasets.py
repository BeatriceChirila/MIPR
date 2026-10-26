import json

# List the separate JSON files you have generated
files_to_combine = [
    "LLM01_PromptInjection.json",
    "LLM07_SystemPromptLeakage.json"
]

combined_data = []

for file_name in files_to_combine:
    try:
        with open(file_name, "r", encoding="utf-8") as f:
            data = json.load(f)
            # Add the items from this file to our master list
            combined_data.extend(data)
            print(f"Loaded {len(data)} items from {file_name}")
    except FileNotFoundError:
        print(f"[!] Warning: {file_name} not found. Skipping.")

# Save the unified dataset
output_file = "final_combined_dataset.json"
with open(output_file, "w", encoding="utf-8") as f:
    json.dump(combined_data, f, indent=2, ensure_ascii=False)

print(f"\nSuccessfully combined a total of {len(combined_data)} examples into {output_file}!")