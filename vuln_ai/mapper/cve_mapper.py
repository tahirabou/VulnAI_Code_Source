import requests
import time
import yaml

def load_config():
    with open("config.yaml", "r") as f:
        return yaml.safe_load(f)

# Mapping manuel basé fiable et sans rate limit
KNOWN_CVE_MAP = {
    "Mirth Connect": [
        {
            "cve_id": "CVE-2023-43208",
            "description": "RCE non authentifié dans Mirth Connect < 4.4.1",
            "cvss_score": 9.8,
            "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cwe": "CWE-502",
            "severity": "CRITICAL"
        }
    ],
    "PHP Laravel": [
        {
            "cve_id": "CVE-2021-21236",
            "description": "Vulnérabilité dans Laravel < 8.4.2",
            "cvss_score": 7.5,
            "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "cwe": "CWE-94",
            "severity": "HIGH"
        }
    ],
    "MySQL": [
        {
            "cve_id": "CVE-2021-2154",
            "description": "Élévation de privilèges dans MySQL 5.7",
            "cvss_score": 4.9,
            "cvss_vector": "AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H",
            "cwe": "CWE-284",
            "severity": "MEDIUM"
        }
    ],
    "wkhtmltopdf": [
        {
            "cve_id": "CVE-2022-35583",
            "description": "SSRF dans wkhtmltopdf 0.12.5",
            "cvss_score": 9.8,
            "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cwe": "CWE-918",
            "severity": "CRITICAL"
        }
    ],
    "Redis": [
        {
            "cve_id": "CVE-2022-0543",
            "description": "RCE via Lua sandbox escape dans Redis",
            "cvss_score": 10.0,
            "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "cwe": "CWE-862",
            "severity": "CRITICAL"
        }
    ],
    "Nginx": [
        {
            "cve_id": "CVE-2021-23017",
            "description": "Off-by-one dans le resolver DNS de Nginx 1.18",
            "cvss_score": 7.7,
            "cvss_vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cwe": "CWE-193",
            "severity": "HIGH"
        }
    ],
    "API REST JWT": [
        {
            "cve_id": "CWE-347",
            "description": "Vérification insuffisante de la signature JWT (algorithm confusion)",
            "cvss_score": 8.1,
            "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            "cwe": "CWE-347",
            "severity": "HIGH"
        }
    ],
    "SSH": [
        {
            "cve_id": "CWE-521",
            "description": "Authentification SSH par mot de passe — bruteforce possible",
            "cvss_score": 6.5,
            "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "cwe": "CWE-521",
            "severity": "MEDIUM"
        }
    ]
}

def search_nvd(keyword: str, config: dict) -> list:
    """Requête optionnelle à l'API NVD pour enrichissement."""
    try:
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": 3,
            "cvssV3Severity": "HIGH"
        }
        headers = {}
        if config["nvd"]["api_key"]:
            headers["apiKey"] = config["nvd"]["api_key"]
        
        resp = requests.get(
            config["nvd"]["base_url"],
            params=params,
            headers=headers,
            timeout=10
        )
        time.sleep(0.7)  # respecter le rate limit
        
        if resp.status_code == 200:
            data = resp.json()
            results = []
            for vuln in data.get("vulnerabilities", []):
                cve = vuln.get("cve", {})
                metrics = cve.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {})
                results.append({
                    "cve_id": cve.get("id", "N/A"),
                    "description": cve.get("descriptions", [{}])[0].get("value", "")[:200],
                    "cvss_score": metrics.get("baseScore", 0),
                    "cvss_vector": metrics.get("vectorString", ""),
                    "severity": metrics.get("baseSeverity", "UNKNOWN")
                })
            return results
    except Exception as e:
        print(f"  [!] NVD non disponible pour '{keyword}': {e}")
    return []

def enrich_report(vulnerabilities: list) -> list:
    config = load_config()
    enriched = []
    
    for vuln in vulnerabilities:
        component = vuln.get("component", "")
        cves = []
        
        # 1. Chercher dans le mapping manuel
        for key, cve_list in KNOWN_CVE_MAP.items():
            if key.lower() in component.lower():
                cves = cve_list
                print(f"  [+] {component} → {[c['cve_id'] for c in cves]} (mapping connu)")
                break
        
        # 2. Si rien trouvé, tenter NVD
        if not cves:
            print(f"  [~] {component} → tentative NVD...")
            cves = search_nvd(component, config)
        
        vuln["cve_mapping"] = cves
        enriched.append(vuln)
    
    return enriched
