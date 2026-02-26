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

import json
import os
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
def run(target, scenarios, timeout, category, difficulty, scenario_id, db_dir, output):
    """Run red team attack scenarios against a target."""
    scenarios_file = scenarios or _default_scenarios_path()
    results_db = RedTeamResultsDB(db_dir)

    orchestrator = RedTeamOrchestrator(
        scenario_file=scenarios_file,
        target_url=target,
        results_db=results_db,
        timeout=timeout,
    )

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


@cli.command()
@click.option("--scenarios", default=None, help="Path to scenarios YAML file")
def stats(scenarios):
    """Show scenario library statistics."""
    from oubliette_dungeon.core import ScenarioLoader

    scenarios_file = scenarios or _default_scenarios_path()
    loader = ScenarioLoader(scenarios_file)
    s = loader.get_statistics()

    click.echo(f"\nScenario Library Statistics")
    click.echo(f"{'=' * 40}")
    click.echo(f"Total Scenarios: {s['total']}")
    click.echo(f"Multi-turn Scenarios: {s['multi_turn_count']}")
    click.echo(f"\nBy Category:")
    for cat, count in sorted(s['by_category'].items()):
        click.echo(f"  {cat}: {count}")
    click.echo(f"\nBy Difficulty:")
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


if __name__ == "__main__":
    cli()
