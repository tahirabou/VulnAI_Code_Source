# VulnAI — Système de Gestion de Vulnérabilités piloté par l'IA

> TP 3 — efrei | Cybersécurité & LLM  
> Environnement : VM Ubuntu 22.04 (VMware) — LLM : Ollama + Mistral (local, CPU-only)  
> Architecture analysée : MediConnect Corp — SaaS médical fictif  

---

## Prérequis

- Ubuntu 22.04 (VM isolée recommandée)
- Python 3.10+
- Docker + Docker Compose
- Ollama installé (`curl -fsSL https://ollama.com/install.sh | sh`)
- Modèle Mistral téléchargé (`ollama pull mistral`)

---

## Installation

```bash
git clone <repo>
cd vuln_ai
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## Lancement du pipeline complet

```bash
python3 main.py
```

Le pipeline exécute automatiquement les 5 étapes :

1. **Parsing** de l'architecture MediConnect (arch_parser.py)
2. **Analyse IA** via Ollama/Mistral (llm_analyzer.py)
3. **Mapping CVE** via API NVD + base locale (cve_mapper.py)
4. **Génération scénarios** MITRE ATT&CK (attack_gen.py)
5. **Rapport HTML + JSON** (report_builder.py)

Résultats dans `reports/` :
- `rapport_mediconnect.html` — rapport principal lisible
- `rapport_brut.json` — données brutes JSON

---

## Structure du projet

```
vuln_ai/
├── main.py                        # Point d'entrée
├── config.yaml                    # Configuration LLM + NVD
├── requirements.txt
├── parser/
│   └── arch_parser.py             # Parsing architecture → objets Pydantic
├── analyzer/
│   └── llm_analyzer.py            # Interface Ollama/Mistral
├── mapper/
│   └── cve_mapper.py              # Mapping CVE (NVD API + base locale)
├── scenarios/
│   └── attack_gen.py              # 3 scénarios MITRE ATT&CK
├── mitigations/
│   └── mitigation_gen.py          # Mitigations priorisées
├── output/
│   └── report_builder.py          # Génération HTML via Jinja2
└── reports/
    ├── rapport_mediconnect.html
    └── rapport_brut.json
```

---

## Lab Scénario A — Mirth Connect RCE (Partie 3)

```bash
cd lab_scenarioA
docker-compose up -d
docker-compose ps   # vérifier que les 3 containers tournent
```

Containers déployés :
- `mirth_vuln` — Mirth Connect 4.4.0 (port 8080)
- `pickle_vuln` — Service Python pickle vulnérable (port 9090)
- `mysql_vuln` — MySQL 5.7 avec credentials App2023! (port 3306)

### Exploitation

```bash
source ~/vuln_ai/venv/bin/activate
python3 exploit_mirth.py       # Étape 1 — RCE confirmé
python3 exploit_mirth_step2.py # Étape 2 — Kill chain complète
```

---

## Configuration LLM

Modifier `config.yaml` pour changer le modèle :

```yaml
llm:
  model: mistral    # ou phi3, llama3
  base_url: http://localhost:11434
  temperature: 0.2
```

---

## Rappel légal

Toutes les techniques présentées sont réservées à des environnements de lab isolés et contrôlés.  
L'exploitation de systèmes sans autorisation est un délit pénal (article 323-1 du Code pénal).
