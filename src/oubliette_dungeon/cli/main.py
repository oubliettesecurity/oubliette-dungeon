"""
Oubliette Dungeon CLI
=====================
Click-based command-line interface for the red team engine.

Usage:
    oubliette-dungeon run --target http://localhost:5000/api/chat
    oubliette-dungeon stats
    oubliette-dungeon serve --port 8666
    oubliette-dungeon demo
    oubliette-dungeon replay results.json
    oubliette-dungeon export --format json --output results.json
"""

import sys

import click

from oubliette_dungeon.core import (
    DEFAULT_TARGET_URL,
    RedTeamOrchestrator,
    _default_scenarios_path,
)
from oubliette_dungeon.storage import RedTeamResultsDB


@click.group()
@click.version_option(version="1.0.0", prog_name="oubliette-dungeon")
def cli():
    """Oubliette Dungeon - AI Red Team Engine"""
    pass


@cli.command()
@click.option("--target", default=DEFAULT_TARGET_URL, help="Target API endpoint URL")
@click.option("--scenarios", default=None, help="Path to scenarios YAML file")
@click.option("--timeout", default=30, type=int, help="Request timeout in seconds")
@click.option("--category", default=None, help="Only run scenarios in this category")
@click.option("--difficulty", default=None, help="Only run scenarios at this difficulty")
@click.option("--scenario-id", default=None, help="Run a specific scenario by ID")
@click.option("--db-dir", default="redteam_results", help="Results database directory")
@click.option("--output", default=None, help="Export benchmark JSON to this path")
@click.option("--offline", is_flag=True, help="Air-gap mode: use local Ollama, zero network")
@click.option("--model", default="llama3", help="Local model for offline mode (default: llama3)")
@click.option("--ollama-url", default="http://localhost:11434", help="Ollama API URL")
@click.option("--ddil-latency", default=0, type=int, help="DDIL: simulated latency in ms")
@click.option("--ddil-drop-rate", default=0.0, type=float, help="DDIL: packet drop rate 0.0-1.0")
@click.option("--ddil-bandwidth", default=0, type=int, help="DDIL: bandwidth limit in kbps")
@click.option("--osef", default=None, help="Export OSEF-format report to this path")
@click.option("--osef-model-id", default=None, help="Model identifier for OSEF report")
def run(target, scenarios, timeout, category, difficulty, scenario_id, db_dir,
        output, offline, model, ollama_url, ddil_latency, ddil_drop_rate,
        ddil_bandwidth, osef, osef_model_id):
    """Run red team attack scenarios against a target."""
    scenarios_file = scenarios or _default_scenarios_path()
    results_db = RedTeamResultsDB(db_dir)

    is_ddil = ddil_latency > 0 or ddil_drop_rate > 0 or ddil_bandwidth > 0

    if offline or is_ddil:
        from oubliette_dungeon.core.offline import OfflineExecutor

        click.echo(f"[OFFLINE] Air-gap mode: using local model '{model}' via Ollama")
        if is_ddil:
            click.echo(
                f"[DDIL] Simulating degraded conditions: "
                f"latency={ddil_latency}ms, drop_rate={ddil_drop_rate}, "
                f"bandwidth={ddil_bandwidth}kbps"
            )

        offline_exec = OfflineExecutor(
            model=model,
            ollama_url=ollama_url,
            timeout=timeout,
            ddil_latency_ms=ddil_latency,
            ddil_drop_rate=ddil_drop_rate,
            ddil_bandwidth_kbps=ddil_bandwidth,
        )

        # Check Ollama availability
        available, msg = offline_exec.check_availability()
        if not available:
            click.echo(f"[OFFLINE] ERROR: {msg}")
            sys.exit(1)
        click.echo(f"[OFFLINE] Ollama connected, model '{model}' ready")

        # Run using offline executor with orchestrator
        orchestrator = RedTeamOrchestrator(
            scenario_file=scenarios_file,
            target_url=target,
            results_db=results_db,
            timeout=timeout,
        )
        # Swap in the offline executor
        orchestrator.executor = offline_exec

        effective_model_id = osef_model_id or f"ollama/{model}"
    else:
        orchestrator = RedTeamOrchestrator(
            scenario_file=scenarios_file,
            target_url=target,
            results_db=results_db,
            timeout=timeout,
        )
        effective_model_id = osef_model_id or target

    if scenario_id:
        results = [orchestrator.run_single_scenario(scenario_id)]
    elif category:
        results = orchestrator.run_by_category(category)
    elif difficulty:
        results = orchestrator.run_by_difficulty(difficulty)
    else:
        results = orchestrator.run_all_scenarios()

    orchestrator.print_summary(results)

    if output:
        orchestrator.export_benchmark(results, output)
        click.echo(f"Benchmark exported to {output}")

    if osef:
        from oubliette_dungeon.core.osef import OSEFReport

        context = {
            "evaluation_type": "adversarial_robustness",
            "scorer": "refusal_aware",
            "environment": "air_gapped" if offline else "unclassified",
        }
        if is_ddil:
            context["ddil"] = {
                "latency_ms": ddil_latency,
                "drop_rate": ddil_drop_rate,
                "bandwidth_kbps": ddil_bandwidth,
            }

        report = OSEFReport.from_results(
            results,
            model_id=effective_model_id,
            session_id=orchestrator.current_session_id,
            context=context,
        )
        report.save(osef)
        click.echo(f"OSEF report exported to {osef}")


@cli.command()
@click.option("--scenarios", default=None, help="Path to scenarios YAML file")
def stats(scenarios):
    """Show scenario library statistics."""
    from oubliette_dungeon.core import ScenarioLoader

    scenarios_file = scenarios or _default_scenarios_path()
    loader = ScenarioLoader(scenarios_file)
    s = loader.get_statistics()

    click.echo("\nScenario Library Statistics")
    click.echo(f"{'=' * 40}")
    click.echo(f"Total Scenarios: {s['total']}")
    click.echo(f"Multi-turn Scenarios: {s['multi_turn_count']}")
    click.echo("\nBy Category:")
    for cat, count in sorted(s['by_category'].items()):
        click.echo(f"  {cat}: {count}")
    click.echo("\nBy Difficulty:")
    for diff, count in sorted(s['by_difficulty'].items()):
        click.echo(f"  {diff}: {count}")


@cli.command()
@click.option("--host", default="0.0.0.0", help="Host to bind to")
@click.option("--port", default=8666, type=int, help="Port to listen on")
@click.option("--debug", is_flag=True, help="Enable debug mode")
def serve(host, port, debug):
    """Start the Dungeon API server."""
    try:
        from oubliette_dungeon.api import create_app
    except ImportError:
        click.echo("Flask is required for the API server.")
        click.echo("Install with: pip install oubliette-dungeon[flask]")
        sys.exit(1)

    app = create_app()
    click.echo(f"Starting Oubliette Dungeon API on {host}:{port}")
    app.run(host=host, port=port, debug=debug)


@cli.command()
@click.option("--port", default=8666, type=int, help="Port for the dashboard")
def demo(port):
    """Start demo mode with fixture data and mock target."""
    click.echo("Starting Oubliette Dungeon in demo mode...")

    # Start mock target
    from oubliette_dungeon.demo.mock_target import create_mock_app

    mock_app = create_mock_app()
    import threading

    mock_thread = threading.Thread(
        target=lambda: mock_app.run(host="127.0.0.1", port=9999, debug=False),
        daemon=True,
    )
    mock_thread.start()
    click.echo("Mock target running on http://127.0.0.1:9999")

    # Seed fixture data
    from oubliette_dungeon.demo import load_fixtures

    load_fixtures()
    click.echo("Fixture data loaded.")

    # Start API server
    try:
        from oubliette_dungeon.api import create_app
    except ImportError:
        click.echo("Flask is required. Install with: pip install oubliette-dungeon[flask]")
        sys.exit(1)

    app = create_app()
    click.echo(f"Dashboard available at http://localhost:{port}")
    app.run(host="0.0.0.0", port=port, debug=False)


@cli.command()
@click.argument("results_file", type=click.Path(exists=True))
@click.option("--target", default=DEFAULT_TARGET_URL, help="Target API endpoint URL")
@click.option("--scenarios", default=None, help="Path to scenarios YAML file")
@click.option("--timeout", default=30, type=int, help="Request timeout")
@click.option("--scenario-ids", default=None, help="Comma-separated scenario IDs to replay")
def replay(results_file, target, scenarios, timeout, scenario_ids):
    """Replay scenarios from a previous results file."""
    scenarios_file = scenarios or _default_scenarios_path()

    orchestrator = RedTeamOrchestrator(
        scenario_file=scenarios_file,
        target_url=target,
        timeout=timeout,
    )

    ids = scenario_ids.split(",") if scenario_ids else None
    results = orchestrator.replay(results_file, scenario_ids=ids)
    orchestrator.print_summary(results)


@cli.command()
@click.option("--format", "fmt", type=click.Choice(["json", "csv"]), default="json", help="Export format")
@click.option("--session", default=None, help="Session ID (default: latest)")
@click.option("--output", required=True, help="Output file path")
@click.option("--db-dir", default="redteam_results", help="Results database directory")
def export(fmt, session, output, db_dir):
    """Export session results to JSON or CSV."""
    db = RedTeamResultsDB(db_dir)

    if fmt == "json":
        db.export_to_json(output, session)
    elif fmt == "csv":
        db.export_to_csv(output, session)

    click.echo(f"Exported to {output}")


@cli.command()
@click.option("--models", required=True, help="Comma-separated Ollama model names")
@click.option("--scenarios", default=None, help="Path to scenarios YAML file")
@click.option("--timeout", default=120, type=int, help="Request timeout per model")
@click.option("--category", default=None, help="Only run scenarios in this category")
@click.option("--difficulty", default=None, help="Only run scenarios at this difficulty")
@click.option("--ollama-url", default="http://localhost:11434", help="Ollama API URL")
@click.option("--output-json", default=None, help="Save comparison as JSON")
@click.option("--output-html", default=None, help="Save comparison as HTML")
@click.option("--db-dir", default="redteam_results", help="Results database directory")
def compare(models, scenarios, timeout, category, difficulty, ollama_url,
            output_json, output_html, db_dir):
    """Compare adversarial resilience across multiple local models."""
    from oubliette_dungeon.core.comparison import ModelComparison
    from oubliette_dungeon.core.offline import OfflineExecutor

    model_list = [m.strip() for m in models.split(",") if m.strip()]
    if len(model_list) < 2:
        click.echo("ERROR: Provide at least 2 models to compare (comma-separated).")
        sys.exit(1)

    scenarios_file = scenarios or _default_scenarios_path()
    results_db = RedTeamResultsDB(db_dir)
    comparison = ModelComparison()

    for model_name in model_list:
        click.echo(f"\n[{model_name}] Running evaluation...")

        executor = OfflineExecutor(
            model=model_name,
            ollama_url=ollama_url,
            timeout=timeout,
        )

        available, msg = executor.check_availability()
        if not available:
            click.echo(f"[{model_name}] SKIPPED: {msg}")
            continue

        orchestrator = RedTeamOrchestrator(
            scenario_file=scenarios_file,
            target_url="offline",
            results_db=results_db,
            timeout=timeout,
        )
        orchestrator.executor = executor

        if category:
            results = orchestrator.run_by_category(category)
        elif difficulty:
            results = orchestrator.run_by_difficulty(difficulty)
        else:
            results = orchestrator.run_all_scenarios()

        comparison.add_results(f"ollama/{model_name}", results)
        click.echo(f"[{model_name}] Done: {len(results)} scenarios evaluated.")

    if not comparison.model_ids:
        click.echo("ERROR: No models were successfully evaluated.")
        sys.exit(1)

    comparison.print_summary()

    if output_json:
        comparison.save_json(output_json)
        click.echo(f"JSON comparison saved to {output_json}")

    if output_html:
        comparison.save_html(output_html)
        click.echo(f"HTML comparison saved to {output_html}")

    if not output_json and not output_html:
        default_path = f"comparison_{RedTeamOrchestrator.__name__}.json"
        comparison.save_json(default_path)
        click.echo(f"Comparison saved to {default_path}")


@cli.command("nist-rmf")
@click.option("--scenarios", default=None, help="Path to scenarios YAML file")
@click.option("--session", default=None, help="Session ID for test results")
@click.option("--db-dir", default="redteam_results", help="Results database directory")
@click.option("--output", default=None, help="Output file path (default: stdout)")
@click.option("--organization", default="Oubliette Security", help="Organization name")
def nist_rmf(scenarios, session, db_dir, output, organization):
    """Generate a NIST AI RMF compliance report.

    Maps attack scenarios and test results to NIST AI Risk Management
    Framework functions (GOVERN, MAP, MEASURE, MANAGE) and outputs a
    markdown compliance report suitable for federal documentation.
    """
    from oubliette_dungeon.core import ScenarioLoader
    from oubliette_dungeon.report.nist_rmf import NISTRMFReport

    scenarios_file = scenarios or _default_scenarios_path()
    loader = ScenarioLoader(scenarios_file)
    all_scenarios = loader.get_all_scenarios()

    results = None
    session_id = session

    if session:
        results_db = RedTeamResultsDB(db_dir)
        session_data = results_db.get_session(session)
        if session_data:
            results = session_data.get("results", [])
        else:
            click.echo(f"Warning: Session '{session}' not found. Generating report without results.")

    report = NISTRMFReport()
    md = report.generate(
        scenarios=all_scenarios,
        results=results,
        session_id=session_id,
        organization=organization,
    )

    if output:
        with open(output, "w", encoding="utf-8") as f:
            f.write(md)
        click.echo(f"NIST AI RMF report written to {output}")
    else:
        click.echo(md)


if __name__ == "__main__":
    cli()
