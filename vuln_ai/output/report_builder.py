from jinja2 import Template
from pathlib import Path
import json

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>Rapport de Vulnérabilités — {{ arch_name }}</title>
<style>
  body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; color: #333; }
  h1 { color: #c0392b; border-bottom: 3px solid #c0392b; padding-bottom: 10px; }
  h2 { color: #2c3e50; margin-top: 40px; }
  h3 { color: #34495e; }
  .summary-box { background: #2c3e50; color: white; padding: 20px; border-radius: 8px; margin: 20px 0; }
  .risk-score { font-size: 48px; font-weight: bold; color: {% if risk_score >= 80 %}#e74c3c{% elif risk_score >= 60 %}#e67e22{% else %}#27ae60{% endif %}; }
  .vuln-card { background: white; border-left: 5px solid #ccc; padding: 15px; margin: 15px 0; border-radius: 4px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
  .CRITICAL { border-left-color: #e74c3c; }
  .HIGH { border-left-color: #e67e22; }
  .MEDIUM { border-left-color: #f39c12; }
  .LOW { border-left-color: #27ae60; }
  .badge { display: inline-block; padding: 3px 10px; border-radius: 12px; font-size: 12px; font-weight: bold; color: white; }
  .badge-CRITICAL { background: #e74c3c; }
  .badge-HIGH { background: #e67e22; }
  .badge-MEDIUM { background: #f39c12; }
  .badge-LOW { background: #27ae60; }
  table { width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; }
  th { background: #2c3e50; color: white; padding: 12px; text-align: left; }
  td { padding: 10px 12px; border-bottom: 1px solid #eee; }
  tr:hover { background: #f9f9f9; }
  .scenario-card { background: white; padding: 20px; margin: 15px 0; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
  .step { background: #ecf0f1; padding: 10px; margin: 8px 0; border-radius: 4px; border-left: 3px solid #3498db; }
  .mitigation-card { background: white; padding: 15px; margin: 15px 0; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
  .IMMEDIATE { border-top: 3px solid #e74c3c; }
  .SHORT_TERM { border-top: 3px solid #e67e22; }
  .LONG_TERM { border-top: 3px solid #27ae60; }
  ol { padding-left: 20px; }
  li { margin: 5px 0; }
</style>
</head>
<body>
<h1>Rapport de Sécurité — {{ arch_name }}</h1>

<div class="summary-box">
  <h2 style="color:white; margin-top:0;">Synthèse Exécutive</h2>
  <div class="risk-score">{{ risk_score }}/100</div>
  <p>Score de risque global</p>
  <p>{{ summary }}</p>
  <p><strong>Vulnérabilités détectées :</strong> {{ vulnerabilities|length }} 
     (CRITICAL: {{ vulnerabilities|selectattr('severity','eq','CRITICAL')|list|length }}, 
      HIGH: {{ vulnerabilities|selectattr('severity','eq','HIGH')|list|length }},
      MEDIUM: {{ vulnerabilities|selectattr('severity','eq','MEDIUM')|list|length }},
      LOW: {{ vulnerabilities|selectattr('severity','eq','LOW')|list|length }})</p>
</div>

<h2>Vulnérabilités Identifiées</h2>
{% for vuln in vulnerabilities %}
<div class="vuln-card {{ vuln.severity }}">
  <h3>{{ vuln.id }} — {{ vuln.component }} 
    <span class="badge badge-{{ vuln.severity }}">{{ vuln.severity }}</span>
    <span style="float:right; font-size:14px;">CVSS: {{ vuln.cvss_score }}</span>
  </h3>
  <p><strong>Type :</strong> {{ vuln.type }}</p>
  <p><strong>Description :</strong> {{ vuln.description }}</p>
  <p><strong>Vecteur d'attaque :</strong> {{ vuln.attack_vector }}</p>
  {% if vuln.cve_hint %}<p><strong>CVE/CWE :</strong> {{ vuln.cve_hint }}</p>{% endif %}
  {% if vuln.cve_mapping %}
  <p><strong>CVE mappées :</strong></p>
  <ul>
    {% for cve in vuln.cve_mapping %}
    <li><strong>{{ cve.cve_id }}</strong> (CVSS {{ cve.cvss_score }}) — {{ cve.description }}</li>
    {% endfor %}
  </ul>
  {% endif %}
</div>
{% endfor %}

<h2>Tableau de Mapping CVE</h2>
<table>
  <tr><th>Composant</th><th>CVE/CWE</th><th>CVSS</th><th>Sévérité</th><th>Description</th></tr>
  {% for vuln in vulnerabilities %}
  {% for cve in vuln.cve_mapping %}
  <tr>
    <td>{{ vuln.component }}</td>
    <td>{{ cve.cve_id }}</td>
    <td>{{ cve.cvss_score }}</td>
    <td><span class="badge badge-{{ cve.severity }}">{{ cve.severity }}</span></td>
    <td>{{ cve.description[:100] }}...</td>
  </tr>
  {% endfor %}
  {% endfor %}
</table>

<h2>Scénarios d'Attaque (MITRE ATT&CK)</h2>
{% for scenario in scenarios %}
<div class="scenario-card">
  <h3>{{ scenario.id }} — {{ scenario.title }}</h3>
  <p><strong>Objectif :</strong> {{ scenario.objective }}</p>
  <p><strong>Point d'entrée :</strong> {{ scenario.entry_point }}</p>
  <p><strong>Acteur :</strong> {{ scenario.threat_actor }}</p>
  <p><strong>CVE utilisées :</strong> {{ scenario.cves_used|join(', ') }}</p>
  <h4>Kill Chain :</h4>
  {% for step in scenario.kill_chain %}
  <div class="step">
    <strong>Étape {{ step.step }} — {{ step.phase }} ({{ step.technique_id }})</strong><br>
    {{ step.technique }} : {{ step.description }}<br>
    <em>Outils : {{ step.tools|join(', ') }}</em><br>
    <em>IoCs : {{ step.iocs|join(' | ') }}</em>
  </div>
  {% endfor %}
  <p><strong>Impact :</strong> {{ scenario.impact }}</p>
  <p><strong>Difficulté de détection :</strong> {{ scenario.detection_difficulty }}</p>
</div>
{% endfor %}

<h2>Stratégies de Mitigation</h2>
{% for mit in mitigations %}
<div class="mitigation-card {{ mit.priority }}">
  <h3>{{ mit.vulnerability_id }} — {{ mit.title }}
    <span class="badge badge-{{ 'CRITICAL' if mit.priority == 'IMMEDIATE' else 'MEDIUM' }}">{{ mit.priority }}</span>
  </h3>
  <p><strong>Composant :</strong> {{ mit.component }} | <strong>Type :</strong> {{ mit.type }} | <strong>Effort :</strong> {{ mit.effort }}</p>
  <p>{{ mit.description }}</p>
  <ol>{% for step in mit.implementation_steps %}<li>{{ step }}</li>{% endfor %}</ol>
  <p><strong>Vérification :</strong> <code>{{ mit.verification }}</code></p>
</div>
{% endfor %}

<footer style="margin-top:60px; text-align:center; color:#aaa; font-size:12px;">
  Rapport généré automatiquement par VulnAI — Environnement académique isolé
</footer>
</body>
</html>"""

def build_report(arch_name: str, analysis: dict, scenarios: list, mitigations: list) -> str:
    Path("reports").mkdir(exist_ok=True)
    
    template = Template(HTML_TEMPLATE)
    html = template.render(
        arch_name=arch_name,
        risk_score=analysis.get("risk_score", 0),
        summary=analysis.get("summary", ""),
        vulnerabilities=analysis.get("vulnerabilities", []),
        scenarios=scenarios,
        mitigations=mitigations
    )
    
    output_path = "reports/rapport_mediconnect.html"
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    
    # Sauvegarder aussi le JSON brut
    with open("reports/rapport_brut.json", "w", encoding="utf-8") as f:
        json.dump({
            "analysis": analysis,
            "scenarios": scenarios,
            "mitigations": mitigations
        }, f, ensure_ascii=False, indent=2)
    
    print(f"[+] Rapport HTML : reports/rapport_mediconnect.html")
    print(f"[+] Rapport JSON : reports/rapport_brut.json")
    return output_path
