from pydantic import BaseModel
from typing import List, Optional
import yaml

class Component(BaseModel):
    name: str
    type: str
    version: Optional[str] = None
    exposure: str
    technologies: List[str] = []
    misconfigurations: List[str] = []

class Architecture(BaseModel):
    name: str
    components: List[Component]
    network_topology: str
    raw_description: str

MEDICONNECT_DESCRIPTION = """
MediConnect Corp est une société de santé numérique qui opère une plateforme SaaS de gestion de dossiers médicaux.

Couche exposition :
- Serveur web Nginx 1.18 exposé sur Internet (ports 80/443), TLS 1.2 uniquement
- Application web PHP 7.4 (Laravel 8.x) hébergée sur Ubuntu 20.04
- API REST publique sur /api/v1 — authentification par token JWT (HS256)
- Interface d'administration sur /admin — authentification basique HTTP

Couche applicative :
- Serveur d'intégration Mirth Connect 4.4.0 (port 8080 interne, exposé via proxy)
- Service de notification interne en Python 3.8 utilisant pickle pour la sérialisation
- Moteur de règles métier en Java 11 (Spring Boot 2.5)
- Service de génération de PDF basé sur wkhtmltopdf 0.12.5

Couche données :
- Base de données MySQL 5.7 accessible depuis l'application (user: app_user, pwd: App2023!)
- Serveur Redis 6.0 sans authentification, accessible en interne sur le port 6379
- Stockage fichiers AWS S3 — bucket public en lecture, credentials stockés dans .env

Couche infrastructure :
- Serveur SSH exposé sur le port 22 — authentification par mot de passe autorisée
- Pas de segmentation réseau entre les couches (flat network)
- Logs applicatifs non centralisés, pas de SIEM
- Pas de WAF ni d'IDS/IPS déployé
- Mises à jour système non automatisées — dernier patch : 8 mois
"""

def parse_architecture() -> Architecture:
    components = [
        Component(
            name="Nginx",
            type="web",
            version="1.18",
            exposure="internet",
            technologies=["Nginx", "TLS 1.2"],
            misconfigurations=["TLS 1.2 uniquement (1.3 non activé)"]
        ),
        Component(
            name="PHP Laravel",
            type="web",
            version="7.4 / Laravel 8.x",
            exposure="internet",
            technologies=["PHP", "Laravel", "Ubuntu 20.04"],
            misconfigurations=[]
        ),
        Component(
            name="API REST JWT",
            type="api",
            version=None,
            exposure="internet",
            technologies=["JWT", "HS256"],
            misconfigurations=["Algorithme HS256 faible", "Pas de rotation de secret"]
        ),
        Component(
            name="Interface Admin HTTP",
            type="web",
            version=None,
            exposure="internet",
            technologies=["HTTP Basic Auth"],
            misconfigurations=["Authentification basique HTTP non chiffrée", "Exposée sur /admin"]
        ),
        Component(
            name="Mirth Connect",
            type="service",
            version="4.4.0",
            exposure="internal",
            technologies=["Mirth Connect", "Java"],
            misconfigurations=["Version vulnérable CVE-2023-43208", "Exposé via proxy"]
        ),
        Component(
            name="Service Pickle Python",
            type="service",
            version="Python 3.8",
            exposure="internal",
            technologies=["Python", "pickle"],
            misconfigurations=["Désérialisation pickle non sécurisée"]
        ),
        Component(
            name="Spring Boot",
            type="service",
            version="Java 11 / Spring Boot 2.5",
            exposure="internal",
            technologies=["Java", "Spring Boot"],
            misconfigurations=[]
        ),
        Component(
            name="wkhtmltopdf",
            type="service",
            version="0.12.5",
            exposure="internal",
            technologies=["wkhtmltopdf"],
            misconfigurations=["Vulnérable SSRF CVE-2022-35583"]
        ),
        Component(
            name="MySQL",
            type="db",
            version="5.7",
            exposure="internal",
            technologies=["MySQL"],
            misconfigurations=["Mot de passe faible App2023!", "Credentials en clair"]
        ),
        Component(
            name="Redis",
            type="db",
            version="6.0",
            exposure="internal",
            technologies=["Redis"],
            misconfigurations=["Aucune authentification", "Port 6379 accessible"]
        ),
        Component(
            name="AWS S3",
            type="storage",
            version=None,
            exposure="internet",
            technologies=["AWS S3"],
            misconfigurations=["Bucket public en lecture", "Credentials dans .env"]
        ),
        Component(
            name="SSH",
            type="infrastructure",
            version=None,
            exposure="internet",
            technologies=["SSH"],
            misconfigurations=["Authentification par mot de passe autorisée", "Port 22 exposé"]
        ),
    ]

    return Architecture(
        name="MediConnect Corp",
        components=components,
        network_topology="Flat network — aucune segmentation entre les couches",
        raw_description=MEDICONNECT_DESCRIPTION
    )
