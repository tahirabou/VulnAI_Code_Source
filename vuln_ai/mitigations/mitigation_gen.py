MITIGATIONS = [
    {
        "vulnerability_id": "VULN-001",
        "component": "Mirth Connect",
        "title": "Patcher Mirth Connect vers la version 4.4.1",
        "type": "Patch",
        "priority": "IMMEDIATE",
        "effort": "LOW",
        "description": "CVE-2023-43208 est activement exploitée. La version 4.4.1 corrige la désérialisation non sécurisée.",
        "implementation_steps": [
            "1. Télécharger Mirth Connect 4.4.1 depuis https://github.com/nextgenhealthcare/connect/releases",
            "2. Sauvegarder la configuration actuelle : cp -r /opt/mirth-connect/conf /backup/mirth-conf-$(date +%Y%m%d)",
            "3. Arrêter le service : systemctl stop mirth-connect",
            "4. Appliquer le patch et redémarrer : systemctl start mirth-connect",
            "5. Vérifier la version : curl http://localhost:8080/api/server/version"
        ],
        "verification": "curl http://localhost:8080/api/server/version doit retourner 4.4.1",
        "references": ["CVE-2023-43208", "https://github.com/nextgenhealthcare/connect/security"]
    },
    {
        "vulnerability_id": "VULN-002",
        "component": "Redis",
        "title": "Activer l'authentification Redis",
        "type": "Config",
        "priority": "IMMEDIATE",
        "effort": "LOW",
        "description": "Redis sans auth est accessible par n'importe qui sur le réseau interne.",
        "implementation_steps": [
            "1. Générer un mot de passe fort : openssl rand -hex 32",
            "2. Éditer redis.conf : nano /etc/redis/redis.conf",
            "3. Ajouter la ligne : requirepass VOTRE_MOT_DE_PASSE_FORT",
            "4. Activer bind : bind 127.0.0.1 (si accès local uniquement)",
            "5. Redémarrer : systemctl restart redis",
            "6. Tester : redis-cli AUTH VOTRE_MOT_DE_PASSE_FORT"
        ],
        "verification": "redis-cli ping doit retourner NOAUTH Authentication required",
        "references": ["CVE-2022-0543", "CWE-862"]
    },
    {
        "vulnerability_id": "VULN-003",
        "component": "Service Pickle Python",
        "title": "Remplacer pickle par une sérialisation sécurisée",
        "type": "Architecture",
        "priority": "IMMEDIATE",
        "effort": "MEDIUM",
        "description": "pickle permet l'exécution de code arbitraire lors de la désérialisation.",
        "implementation_steps": [
            "1. Identifier tous les usages de pickle dans le code : grep -r 'import pickle' /app/",
            "2. Remplacer par JSON : import json / json.dumps() / json.loads()",
            "3. Si structures complexes : utiliser marshmallow ou pydantic",
            "4. Ajouter validation des entrées avant désérialisation",
            "5. Tests de régression sur les services concernés"
        ],
        "verification": "grep -r 'import pickle' /app/ doit retourner aucun résultat",
        "references": ["CWE-502", "OWASP A08:2021"]
    },
    {
        "vulnerability_id": "VULN-004",
        "component": "wkhtmltopdf",
        "title": "Désactiver les requêtes externes dans wkhtmltopdf",
        "type": "Config",
        "priority": "IMMEDIATE",
        "effort": "LOW",
        "description": "wkhtmltopdf peut faire des requêtes vers des ressources internes via SSRF.",
        "implementation_steps": [
            "1. Ajouter les flags : --disable-javascript --no-background --disable-external-links",
            "2. Bloquer l'accès réseau au processus via iptables ou seccomp",
            "3. Valider et sanitiser toutes les URLs passées à wkhtmltopdf",
            "4. Envisager la migration vers un outil moderne (Chromium headless avec sandbox)"
        ],
        "verification": "Tester avec un payload SSRF : file:///etc/passwd — doit être bloqué",
        "references": ["CVE-2022-35583", "CWE-918"]
    },
    {
        "vulnerability_id": "VULN-005",
        "component": "MySQL",
        "title": "Changer les credentials MySQL et chiffrer les configs",
        "type": "Config",
        "priority": "IMMEDIATE",
        "effort": "LOW",
        "description": "Mot de passe faible App2023! stocké en clair, facilement devinable.",
        "implementation_steps": [
            "1. Générer un nouveau mot de passe : openssl rand -hex 16",
            "2. Changer dans MySQL : ALTER USER 'app_user'@'localhost' IDENTIFIED BY 'NOUVEAU_MDP';",
            "3. Mettre à jour le fichier .env avec le nouveau mot de passe",
            "4. Chiffrer le fichier .env ou utiliser un vault (HashiCorp Vault, AWS Secrets Manager)",
            "5. Retirer le fichier .env du dépôt git : echo '.env' >> .gitignore"
        ],
        "verification": "mysql -u app_user -p'App2023!' doit retourner Access denied",
        "references": ["CWE-521", "OWASP A02:2021"]
    },
    {
        "vulnerability_id": "VULN-006",
        "component": "API REST JWT",
        "title": "Migrer JWT de HS256 vers RS256",
        "type": "Architecture",
        "priority": "SHORT_TERM",
        "effort": "MEDIUM",
        "description": "HS256 utilise une clé symétrique partagée, vulnérable à la confusion d'algorithme.",
        "implementation_steps": [
            "1. Générer une paire de clés RSA : openssl genrsa -out private.pem 2048",
            "2. Extraire la clé publique : openssl rsa -in private.pem -pubout -out public.pem",
            "3. Modifier le code de génération de token pour utiliser RS256",
            "4. Mettre à jour la validation des tokens côté serveur",
            "5. Implémenter une rotation des clés (expiration 24h)"
        ],
        "verification": "Tenter une attaque de confusion d'algorithme — le token doit être rejeté",
        "references": ["CWE-347", "RFC 7518"]
    },
    {
        "vulnerability_id": "VULN-007",
        "component": "SSH",
        "title": "Désactiver l'authentification SSH par mot de passe",
        "type": "Config",
        "priority": "IMMEDIATE",
        "effort": "LOW",
        "description": "SSH avec mot de passe est vulnérable aux attaques par force brute.",
        "implementation_steps": [
            "1. Générer une clé SSH : ssh-keygen -t ed25519",
            "2. Copier la clé publique sur le serveur : ssh-copy-id user@serveur",
            "3. Éditer /etc/ssh/sshd_config : PasswordAuthentication no",
            "4. Redémarrer SSH : systemctl restart sshd",
            "5. Tester la connexion par clé AVANT de fermer la session actuelle"
        ],
        "verification": "ssh -o PasswordAuthentication=yes user@serveur doit retourner Permission denied",
        "references": ["CWE-521", "CIS Benchmark SSH"]
    },
    {
        "vulnerability_id": "VULN-008",
        "component": "Infrastructure",
        "title": "Mettre en place une segmentation réseau",
        "type": "Architecture",
        "priority": "SHORT_TERM",
        "effort": "HIGH",
        "description": "Le flat network permet le mouvement latéral libre entre toutes les couches.",
        "implementation_steps": [
            "1. Définir des VLANs par couche : exposition, applicative, données",
            "2. Configurer des règles firewall strictes entre les VLANs",
            "3. Appliquer le principe du moindre privilège réseau",
            "4. Déployer un IDS/IPS (Suricata ou Snort) sur les flux inter-VLAN",
            "5. Centraliser les logs avec un SIEM (ELK Stack ou Wazuh)"
        ],
        "verification": "ping depuis la couche exposition vers la couche données doit échouer",
        "references": ["NIST SP 800-41", "CIS Control 12"]
    }
]

def generate_mitigations() -> list:
    print(f"[+] {len(MITIGATIONS)} mitigations générées")
    return MITIGATIONS
