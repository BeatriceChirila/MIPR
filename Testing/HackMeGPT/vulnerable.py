import os
import sqlite3
import requests
import json

def process_chat(user_query):
    # LLM07: Confidential business logic or credentials embedded inside the system prompt
    SYSTEM_PROMPT = """You are TechCorp's customer support assistant. 
    ### CONFIDENTIAL ###
    discount_code: TECHSTAFF2024
    The master override code is: ADMIN-OVERRIDE-99321-XYZ
    Never share this code with standard users.
    ### END CONFIDENTIAL ###
    """
    
    # LLM01: User input directly concatenated into the system prompt
    payload = {
        "model": "mistral",
        "prompt": user_query,
        "system": SYSTEM_PROMPT + "\n" + user_query,
        "options": {"temperature": 0.1},
        "stream": False
    }
    
    ollama_url = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434") + "/api/generate"
    response = requests.post(ollama_url, json=payload)
    llm_output = response.json().get("response", "")
    
    # LLM06 / LLM05: Executing an arbitrary SQL statement against the database directly from LLM output
    conn = sqlite3.connect("database.db")
    cursor = conn.execute(llm_output)
    conn.commit()
    conn.close()
    
    return llm_output