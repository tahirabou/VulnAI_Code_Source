from rich.console import Console
from rich.panel import Panel
from parser.arch_parser import parse_architecture
from analyzer.llm_analyzer import analyze_architecture
from mapper.cve_mapper import enrich_report
from scenarios.attack_gen import generate_scenarios
from mitigations.mitigation_gen import generate_mitigations
from output.report_builder import build_report

console = Console()

def main():
    console.print(Panel.fit(
        "[bold red]VulnAI — Système de Gestion de Vulnérabilités[/bold red]\n"
        "[dim]Environnement académique — Lab isolé[/dim]",
        border_style="red"
    ))

    # Étape 1 — Parser l'architecture
    console.print("\n[bold cyan][1/5] Parsing de l'architecture MediConnect...[/bold cyan]")
    architecture = parse_architecture()
    console.print(f"[green]  ✓ {len(architecture.components)} composants identifiés[/green]")

    # Étape 2 — Analyse LLM via Ollama
    console.print("\n[bold cyan][2/5] Analyse IA via Ollama (llama3)...[/bold cyan]")
    console.print("[dim]  Cette étape peut prendre 1-3 minutes en mode CPU...[/dim]")
    analysis = analyze_architecture(architecture)

    # Étape 3 — Enrichissement CVE
    console.print("\n[bold cyan][3/5] Mapping CVE (NVD + base locale)...[/bold cyan]")
    analysis["vulnerabilities"] = enrich_report(analysis.get("vulnerabilities", []))
    console.print(f"[green]  ✓ Enrichissement terminé[/green]")

    # Étape 4 — Génération des scénarios
    console.print("\n[bold cyan][4/5] Génération des scénarios d'attaque MITRE ATT&CK...[/bold cyan]")
    scenarios = generate_scenarios()
    console.print(f"[green]  ✓ {len(scenarios)} scénarios générés[/green]")

    # Étape 5 — Mitigations + rapport
    console.print("\n[bold cyan][5/5] Génération des mitigations et du rapport...[/bold cyan]")
    mitigations = generate_mitigations()
    report_path = build_report(architecture.name, analysis, scenarios, mitigations)

    console.print(Panel.fit(
        f"[bold green]Analyse terminée ![/bold green]\n"
        f"Rapport : [cyan]{report_path}[/cyan]\n"
        f"Score de risque global : [red]{analysis.get('risk_score', '?')}/100[/red]",
        border_style="green"
    ))

if __name__ == "__main__":
    main()
