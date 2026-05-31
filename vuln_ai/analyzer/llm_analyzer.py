import requests
import json
import yaml
from pathlib import Path

def load_config():
    with open("config.yaml", "r") as f:
        return yaml.safe_load(f)

SYSTEM_PROMPT = """Tu es un expert cybersécurité. Retourne UNIQUEMENT un JSON valide, sans markdown :
{"vulnerabilities":[{"id":"VULN-001","component":"nom","type":"type","severity":"CRITICAL","cvss_score":9.8,"description":"desc","attack_vector":"vecteur","cve_hint":"CVE"}],"risk_score":85,"summary":"synthese"}
Trouve minimum 8 vulnérabilités."""

def analyze_architecture(architecture) -> dict:
    config = load_config()
    
    prompt = f"""Architecture MediConnect:
{architecture.raw_description[:1500]}
Retourne uniquement le JSON."""

    payload = {
        "model": config["llm"]["model"],
        "prompt": f"[SYSTEM]\n{SYSTEM_PROMPT}\n[USER]\n{prompt}",
        "stream": False,
        "options": {
            "temperature": config["llm"]["temperature"]
        }
    }

    print("[*] Envoi de la requête à Ollama...")
    response = requests.post(
        f"{config['llm']['base_url']}/api/generate",
        json=payload,
        timeout=600
    )
    response.raise_for_status()
    
    raw = response.json()["response"].strip()
    
    # Nettoyage au cas où le modèle ajoute des balises markdown
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
    raw = raw.strip()
    
    try:
        result = json.loads(raw)
        print(f"[+] Analyse terminée — {len(result.get('vulnerabilities', []))} vulnérabilités détectées")
        return result
    except json.JSONDecodeError as e:
        print(f"[-] Erreur parsing JSON : {e}")
        print(f"[-] Réponse brute : {raw[:500]}")
        return {"vulnerabilities": [], "risk_score": 0, "summary": "Erreur d'analyse", "raw": raw}
