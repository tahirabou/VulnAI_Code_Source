import requests
import json
import yaml

def load_config():
    with open("config.yaml", "r") as f:
        return yaml.safe_load(f)

SCENARIOS = [
    {
        "id": "SCN-A",
        "title": "Compromission totale via Mirth Connect + Pickle",
        "objective": "Accès root + exfiltration des dossiers médicaux",
        "entry_point": "CVE-2023-43208 (Mirth Connect RCE non authentifié)",
        "threat_actor": "APT ciblé — attaquant externe motivé financièrement",
        "cves_used": ["CVE-2023-43208", "CWE-502"],
        "kill_chain": [
            {
                "step": 1,
                "phase": "Initial Access",
                "technique_id": "T1190",
                "technique": "Exploit Public-Facing Application",
                "description": "Exploitation de CVE-2023-43208 sur Mirth Connect 4.4.0 exposé via proxy",
                "tools": ["curl", "exploit-db", "python exploit script"],
                "iocs": ["Requêtes POST anormales sur /api/server/", "User-agent inhabituel"]
            },
            {
                "step": 2,
                "phase": "Execution",
                "technique_id": "T1059",
                "technique": "Command and Scripting Interpreter",
                "description": "Exécution de commandes via le RCE obtenu — découverte du service Pickle interne",
                "tools": ["bash", "netcat"],
                "iocs": ["Processus enfants de Mirth Connect", "Connexions réseau sortantes"]
            },
            {
                "step": 3,
                "phase": "Lateral Movement",
                "technique_id": "T1210",
                "technique": "Exploitation of Remote Services",
                "description": "Injection d'un payload pickle malveillant dans le service de notification Python",
                "tools": ["pickle payload generator"],
                "iocs": ["Trafic inhabituel sur le port du service Python"]
            },
            {
                "step": 4,
                "phase": "Collection",
                "technique_id": "T1005",
                "technique": "Data from Local System",
                "description": "Accès à la base MySQL avec les credentials trouvés en clair (App2023!)",
                "tools": ["mysql-client"],
                "iocs": ["Connexions MySQL depuis IP inhabituelle"]
            },
            {
                "step": 5,
                "phase": "Exfiltration",
                "technique_id": "T1567",
                "technique": "Exfiltration Over Web Service",
                "description": "Exfiltration des dossiers médicaux via le bucket S3 public",
                "tools": ["aws-cli", "curl"],
                "iocs": ["Volume de données sortantes anormal", "Accès S3 depuis IP inconnue"]
            }
        ],
        "impact": "CRITIQUE — Violation RGPD/HIPAA, fuite de données de santé, prise de contrôle totale",
        "detection_difficulty": "HIGH"
    },
    {
        "id": "SCN-B",
        "title": "Exfiltration via SSRF + wkhtmltopdf",
        "objective": "Accès aux ressources internes et credentials cloud AWS",
        "entry_point": "CVE-2022-35583 (wkhtmltopdf SSRF)",
        "threat_actor": "Attaquant opportuniste — scan automatisé",
        "cves_used": ["CVE-2022-35583"],
        "kill_chain": [
            {
                "step": 1,
                "phase": "Initial Access",
                "technique_id": "T1190",
                "technique": "Exploit Public-Facing Application",
                "description": "Injection d'une URL malveillante dans l'endpoint de génération PDF",
                "tools": ["curl", "Burp Suite"],
                "iocs": ["URLs file:// ou http://169.254.169.254 dans les requêtes PDF"]
            },
            {
                "step": 2,
                "phase": "Discovery",
                "technique_id": "T1580",
                "technique": "Cloud Infrastructure Discovery",
                "description": "Accès au metadata service AWS (169.254.169.254) via SSRF",
                "tools": ["wkhtmltopdf SSRF payload"],
                "iocs": ["Requêtes vers 169.254.169.254 dans les logs"]
            },
            {
                "step": 3,
                "phase": "Credential Access",
                "technique_id": "T1552",
                "technique": "Unsecured Credentials",
                "description": "Vol des credentials IAM temporaires depuis le metadata service",
                "tools": ["curl"],
                "iocs": ["Utilisation de credentials IAM depuis IP externe"]
            },
            {
                "step": 4,
                "phase": "Exfiltration",
                "technique_id": "T1530",
                "technique": "Data from Cloud Storage Object",
                "description": "Accès et exfiltration du bucket S3 public avec les credentials volés",
                "tools": ["aws-cli"],
                "iocs": ["Accès massif au bucket S3 depuis IP inconnue"]
            }
        ],
        "impact": "ÉLEVÉ — Exfiltration données S3, pivot vers autres services AWS",
        "detection_difficulty": "MEDIUM"
    },
    {
        "id": "SCN-C",
        "title": "Escalade de privilèges via Redis non authentifié",
        "objective": "Persistance et mouvement latéral",
        "entry_point": "Redis 6.0 sans authentification (port 6379)",
        "threat_actor": "Attaquant interne ou ayant un accès réseau",
        "cves_used": ["CVE-2022-0543"],
        "kill_chain": [
            {
                "step": 1,
                "phase": "Initial Access",
                "technique_id": "T1133",
                "technique": "External Remote Services",
                "description": "Connexion directe à Redis sans authentification sur le port 6379",
                "tools": ["redis-cli"],
                "iocs": ["Connexion Redis depuis IP inhabituelle"]
            },
            {
                "step": 2,
                "phase": "Persistence",
                "technique_id": "T1053",
                "technique": "Scheduled Task/Job",
                "description": "Injection d'une crontab via Redis CONFIG SET dir + CONFIG SET dbfilename",
                "tools": ["redis-cli"],
                "iocs": ["Modification de la configuration Redis", "Nouveau fichier cron"]
            },
            {
                "step": 3,
                "phase": "Execution",
                "technique_id": "T1059",
                "technique": "Command and Scripting Interpreter",
                "description": "Exécution du reverse shell via la crontab injectée",
                "tools": ["netcat", "bash"],
                "iocs": ["Connexion sortante depuis le serveur Redis", "Processus bash inattendu"]
            },
            {
                "step": 4,
                "phase": "Collection",
                "technique_id": "T1005",
                "technique": "Data from Local System",
                "description": "Accès à MySQL avec les credentials trouvés dans les fichiers de config",
                "tools": ["mysql-client", "grep"],
                "iocs": ["Accès aux fichiers de configuration", "Requêtes MySQL inhabituelles"]
            }
        ],
        "impact": "ÉLEVÉ — Persistance, accès aux données applicatives, mouvement latéral",
        "detection_difficulty": "LOW"
    }
]

def generate_scenarios() -> list:
    print(f"[+] {len(SCENARIOS)} scénarios d'attaque générés (MITRE ATT&CK)")
    return SCENARIOS
