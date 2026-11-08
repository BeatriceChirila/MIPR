import json
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
import joblib
from sentence_transformers import SentenceTransformer
import time

def load_data(file_path):
    print(f"[*] Încărcăm datele din {file_path}...")
    with open(file_path, "r", encoding="utf-8") as f:
        dataset = json.load(f)
    
    texts = []
    labels = []
    
    for item in dataset:
        code = item.get("code", "")
        # Luăm prima categorie. Dacă lista e goală, punem "SAFE"
        categories = item.get("categories", ["SAFE"])
        label = categories[0] if categories else "SAFE"
        
        if code.strip():
            texts.append(code)
            labels.append(label)
            
    print(f"[+] Am încărcat {len(texts)} exemple valide.")
    return texts, labels

def main():
    dataset_path = "master_dataset_hf.json"
    model_out_path = "model_tl.joblib"
    
    texts, labels = load_data(dataset_path)
    
    # 1. TRANSFER LEARNING: Folosim un model pre-antrenat Hugging Face pentru Feature Extraction
    # 'all-MiniLM-L6-v2' este foarte rapid și funcționează excelent pentru extragere de semantică
    print("\n[*] Descărcăm/Încărcăm modelul pre-antrenat (Hugging Face) pentru embeddings...")
    print("    (Acest pas poate dura 1-2 minute la prima rulare)")
    embedder = SentenceTransformer('all-MiniLM-L6-v2')
    
    print("[*] Transformăm codul sursă în vectori semantici (Transfer Learning)...")
    start_time = time.time()
    X = embedder.encode(texts, show_progress_bar=True)
    print(f"[+] Embeddings generate în {time.time() - start_time:.2f} secunde.")
    
    # 2. Împărțim datele (Train: 80%, Test: 20%) pentru Etapa 3
    print("\n[*] Împărțim datele: 80% antrenare, 20% testare...")
    X_train, X_test, y_train, y_test = train_test_split(X, labels, test_size=0.2, random_state=42, stratify=labels)
    
    # 3. Antrenăm clasificatorul final folosind class_weight='balanced' pentru clasele minoritare
    print("[*] Antrenăm clasificatorul (Logistic Regression)...")
    clf = LogisticRegression(max_iter=2000, class_weight='balanced', random_state=42)
    clf.fit(X_train, y_train)
    
    # 4. Evaluăm modelul
    print("\n[*] Evaluăm modelul pe setul de test...")
    y_pred = clf.predict(X_test)
    
    print("\n=== REZULTATE ETAPA 3: TRANSFER LEARNING ===")
    print(classification_report(y_test, y_pred, zero_division=0))
    
    # 5. Salvăm modelul pentru a fi folosit în scriptul de scanare (Etapa 5)
    print(f"\n[*] Salvăm modelul antrenat în '{model_out_path}'...")
    joblib.dump({'classifier': clf, 'embedder_name': 'all-MiniLM-L6-v2'}, model_out_path)
    print("[+] Gata! Modelul a fost salvat cu succes.")

if __name__ == "__main__":
    main()