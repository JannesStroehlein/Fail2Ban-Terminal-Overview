import os
import sys

import rich.align
from dotenv import load_dotenv
from prometheus_api_client.exceptions import PrometheusApiClientException

# Import the PrometheusConnect class and its specific exceptions
from prometheus_api_client.prometheus_connect import PrometheusConnect
from requests.auth import HTTPBasicAuth
from rich import box
from rich.console import Console
from rich.table import Table

# Load environment variables
load_dotenv()

PROMETHEUS_URL = os.getenv("PROMETHEUS_URL", "http://localhost:9090").rstrip("/")
PROMETHEUS_USER = os.getenv("PROMETHEUS_USER")
PROMETHEUS_PASSWORD = os.getenv("PROMETHEUS_PASSWORD")

VALUE_GRADIENT_STOPS = [
    (0.0, "#00ff00"),  # Green at 0
    (0.5, "#ffff00"),  # Yellow at 50% of max
    (1.0, "#ff0000"),  # Red at max
]

# Initialize Rich console
console = Console()


def get_gradient_color(position: float, stops: list[tuple[float, str]]) -> str | None:
    """
    Calculates a color along a gradient defined by specific color stops.

    Args:
        position (float): The current position to evaluate.
        stops (list[tuple[float, str]]): A list of (position, hex_color) stops.
            Example: [(0.0, "#00ff00"), (0.8, "#ffff00"), (1.0, "#ff0000")]

    Returns:
        str: A hex color code (e.g., '#80ff00').
    """
    if not stops:
        raise ValueError("At least one color stop must be provided.")

    position = max(0.0, min(1.0, position))  # Clamp position to [0.0, 1.0]

    # Helper to convert hex to RGB
    def hex_to_rgb(hex_code: str) -> tuple[int, int, int]:
        h = hex_code.lstrip("#")
        return (int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16))

    # Ensure stops are sorted by position so the interpolation math works
    stops = sorted(stops, key=lambda x: x[0])

    # Edge cases: position falls outside the bounds of the defined stops
    if position <= stops[0][0]:
        return stops[0][1]
    if position >= stops[-1][0]:
        return stops[-1][1]

    # Find which segment the position falls into
    for i in range(len(stops) - 1):
        pos1, color1 = stops[i]
        pos2, color2 = stops[i + 1]

        if pos1 <= position <= pos2:
            # How far along are we between these two specific stops? (0.0 to 1.0)
            local_pos = (position - pos1) / (pos2 - pos1)

            r1, g1, b1 = hex_to_rgb(color1)
            r2, g2, b2 = hex_to_rgb(color2)

            # Interpolate the RGB values
            r = int(r1 + (r2 - r1) * local_pos)
            g = int(g1 + (g2 - g1) * local_pos)
            b = int(b1 + (b2 - b1) * local_pos)

            return f"#{r:02x}{g:02x}{b:02x}"


def get_prom_client():
    auth: HTTPBasicAuth | None = None

    if PROMETHEUS_USER and PROMETHEUS_PASSWORD:
        auth = HTTPBasicAuth(PROMETHEUS_USER, PROMETHEUS_PASSWORD)

    prom = PrometheusConnect(
        url=PROMETHEUS_URL,
        disable_ssl=False,
        auth=(auth if auth else None),  # ty:ignore[invalid-argument-type]
    )
    return prom


def fetch_fail2ban_metrics():
    """Fetches and parses fail2ban metrics using prometheus_api_client."""

    try:
        prom = get_prom_client()

        base_query = '{__name__=~"f2b_.*|fail2ban_.*"}'
        base_data = prom.custom_query(query=base_query)

        bans_1h_query = 'increase({__name__=~"f2b_jail_banned_total|fail2ban_jail_banned_total"}[1h])'
        fails_1h_query = 'increase({__name__=~"f2b_jail_failed_total|fail2ban_jail_failed_total"}[1h])'

        bans_1h_data = prom.custom_query(query=bans_1h_query)
        fails_1h_data = prom.custom_query(query=fails_1h_query)

    except PrometheusApiClientException as e:
        console.print(f"[bold red]ERROR:[/bold red] Prometheus API exception: {e}")
        sys.exit(1)
    except Exception as e:
        console.print(
            f"[bold red]ERROR:[/bold red] Failed to connect to Prometheus: {e}"
        )
        sys.exit(1)

    jails_data = {}
    instances = set()

    # Process Base Data (Current & Totals)
    for result in base_data:
        metric = result.get("metric", {})
        metric_name = metric.get("__name__", "")
        jail_name = metric.get("jail")
        instance_name = metric.get("instance", "unknown")

        if not jail_name:
            continue

        instances.add(instance_name)
        value = int(result.get("value", [0, "0"])[1])

        if jail_name not in jails_data:
            jails_data[jail_name] = {}

        if instance_name not in jails_data[jail_name]:
            jails_data[jail_name][instance_name] = {
                "banned_current": 0,
                "banned_total": 0,
                "banned_1h": 0,
                "failed_current": 0,
                "failed_total": 0,
                "failed_1h": 0,
            }

        stats = jails_data[jail_name][instance_name]

        if "banned_current" in metric_name:
            stats["banned_current"] = value
        elif "banned_total" in metric_name:
            stats["banned_total"] = value
        elif "failed_current" in metric_name:
            stats["failed_current"] = value
        elif "failed_total" in metric_name:
            stats["failed_total"] = value

    # Helper function to process the 1h increase data
    def merge_1h_data(data, stat_key):
        for result in data:
            metric = result.get("metric", {})
            jail_name = metric.get("jail")
            instance_name = metric.get("instance", "unknown")

            if not jail_name or jail_name not in jails_data:
                continue

            if instance_name in jails_data[jail_name]:
                # increase() returns extrapolated floats, so we round to nearest integer
                raw_value = float(result.get("value", [0, 0.0])[1])
                jails_data[jail_name][instance_name][stat_key] = int(round(raw_value))

    # Merge the 1h data into our main dictionary
    merge_1h_data(bans_1h_data, "banned_1h")
    merge_1h_data(fails_1h_data, "failed_1h")

    return jails_data, sorted(list(instances))


def format_metric_cur(value, gradient_max) -> str:
    if value == 0:
        return f"[bright_black]{value}[/bright_black]"

    position = value / gradient_max if value > 0 else 0.0
    color = get_gradient_color(position, VALUE_GRADIENT_STOPS)
    return f"[bold {color}]{value}[/bold {color}]"


def format_metric_last_h(value, gradient_max) -> str:
    if value == 0:
        return f"[bright_black]{value}[/bright_black]"

    if value < 0:
        return f"[bold red]{value}[/bold red]"

    position = value / gradient_max if value > 0 else 0.0
    color = get_gradient_color(position, VALUE_GRADIENT_STOPS)
    return f"[bold {color}]{value}[/bold {color}]"


def format_metric_total(value) -> str:
    return str(value)


def create_inner_grid(
    bans_cur, bans_last_h, bans_total, fails_cur, fails_last_h, fails_total
):
    """Creates a borderless Rich Grid to perfectly align sub-columns."""
    grid = Table.grid(padding=(0, 0))

    # Define exact widths for each element in the string to enforce alignment
    grid.add_column(justify="left", width=7)  # Label ("Bans:" / "Fails:")
    grid.add_column(justify="center", width=5)  # Current Value
    grid.add_column(justify="center", width=3)  # Slash 1
    grid.add_column(justify="center", width=5)  # 1h Value
    grid.add_column(justify="center", width=3)  # Slash 2
    grid.add_column(justify="center", width=5)  # Total Value

    # Format colors
    bans_cur_str = format_metric_cur(bans_cur, 30)
    bans_last_h_str = format_metric_last_h(bans_last_h, 10)
    bans_total_str = format_metric_total(bans_total)

    fails_cur_str = format_metric_cur(fails_cur, 10)
    fails_last_h_str = format_metric_last_h(fails_last_h, 100)
    fails_total_str = format_metric_total(fails_total)

    # Add the rows into our mini-grid
    grid.add_row("Bans:", bans_cur_str, "/", bans_last_h_str, "/", bans_total_str)
    grid.add_row("Fails:", fails_cur_str, "/", fails_last_h_str, "/", fails_total_str)

    return grid


def display_matrix_table(jails_data, instances):
    """Renders the statistics in a Jail (Rows) x Nodes (Columns) matrix."""
    table = Table(
        title="Fail2Ban Statistics Matrix (Current / 1h / Total)",
        box=box.ROUNDED,
        header_style="bold cyan",
        title_style="bold bright_cyan",
        title_justify="left",
        show_lines=True,
    )

    table.add_column("Jail Name", style="bold green", no_wrap=True)

    for instance in instances:
        table.add_column(f"Node: {instance}", justify="center")

    for jail in sorted(jails_data.keys()):
        row = [jail]

        for instance in instances:
            stats = jails_data[jail].get(instance)

            if stats is None:
                row.append("[dim]N/A[/dim]")
                continue

            # Instead of manually padding strings, we pass the raw data
            # to our helper which returns a perfectly aligned Rich grid.
            cell_grid = create_inner_grid(
                bans_cur=stats["banned_current"],
                bans_last_h=stats["banned_1h"],
                bans_total=stats["banned_total"],
                fails_cur=stats["failed_current"],
                fails_last_h=stats["failed_1h"],
                fails_total=stats["failed_total"],
            )

            row.append(cell_grid)

        table.add_row(*row)

    console.print(rich.align.Align.center(table))
    console.print()


if __name__ == "__main__":
    jails_data, instances = fetch_fail2ban_metrics()

    if not jails_data:
        console.print(
            "[bold yellow]WARN:[/bold yellow] No Fail2Ban metrics found in Prometheus."
        )
        sys.exit(0)

    display_matrix_table(jails_data, instances)
