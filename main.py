import os
import sys
from datetime import datetime, timedelta

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

# Inline sparkline settings (kept tiny to fit a ~60x15 char UI)
SPARK_BLOCKS = "▁▂▃▄▅▆▇█"
SPARK_WIDTH = 7  # number of buckets / chars
SPARK_RANGE = timedelta(hours=24)

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


def render_sparkline(values: list[float], width: int = SPARK_WIDTH) -> str:
    """Renders a tiny Unicode block sparkline from a series of values.

    Scales relative to the series' own min/max. Each block is color-graded by
    its height so spikes stand out. Returns a fixed-width, dim-padded string.
    """
    if not values:
        return f"[bright_black]{'·' * width}[/bright_black]"

    # Keep the most recent `width` points
    series = values[-width:]

    lo = min(series)
    hi = max(series)
    span = hi - lo

    chars = []
    for v in series:
        # Position within the series' own range -> block + gradient color
        norm = (v - lo) / span if span > 0 else 0.0
        idx = int(round(norm * (len(SPARK_BLOCKS) - 1)))
        color = get_gradient_color(norm, VALUE_GRADIENT_STOPS)
        chars.append(f"[{color}]{SPARK_BLOCKS[idx]}[/{color}]")

    # Left-pad with dim dots so all sparklines align to a fixed width
    pad = width - len(series)
    prefix = f"[bright_black]{'·' * pad}[/bright_black]" if pad > 0 else ""
    return prefix + "".join(chars)


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
        bans_1d_query = 'increase({__name__=~"f2b_jail_banned_total|fail2ban_jail_banned_total"}[1d])'
        fails_1d_query = 'increase({__name__=~"f2b_jail_failed_total|fail2ban_jail_failed_total"}[1d])'

        bans_1h_data = prom.custom_query(query=bans_1h_query)
        fails_1h_data = prom.custom_query(query=fails_1h_query)
        bans_1d_data = prom.custom_query(query=bans_1d_query)
        fails_1d_data = prom.custom_query(query=fails_1d_query)

        # Range data for inline sparklines (trend over SPARK_RANGE)
        end_time = datetime.now()
        start_time = end_time - SPARK_RANGE
        step = f"{int(SPARK_RANGE.total_seconds() // SPARK_WIDTH)}s"

        bans_series_query = (
            '{__name__=~"f2b_jail_banned_current|fail2ban_jail_banned_current"}'
        )
        fails_series_query = (
            'rate({__name__=~"f2b_jail_failed_total|fail2ban_jail_failed_total"}[5m])'
        )

        bans_series_data = prom.custom_query_range(
            query=bans_series_query,
            start_time=start_time,
            end_time=end_time,
            step=step,
        )
        fails_series_data = prom.custom_query_range(
            query=fails_series_query,
            start_time=start_time,
            end_time=end_time,
            step=step,
        )

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

    # Process Base Data (discover jails + instances)
    for result in base_data:
        metric = result.get("metric", {})
        jail_name = metric.get("jail")
        instance_name = metric.get("instance", "unknown")

        if not jail_name:
            continue

        instances.add(instance_name)

        if jail_name not in jails_data:
            jails_data[jail_name] = {}

        if instance_name not in jails_data[jail_name]:
            jails_data[jail_name][instance_name] = {
                "banned_1h": 0,
                "banned_1d": 0,
                "failed_1h": 0,
                "failed_1d": 0,
                "bans_series": [],
                "fails_series": [],
            }

    # Helper to process increase() data (1h / 1d windows)
    def merge_increase(data, stat_key):
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

    # Merge the windowed increase data into our main dictionary
    merge_increase(bans_1h_data, "banned_1h")
    merge_increase(fails_1h_data, "failed_1h")
    merge_increase(bans_1d_data, "banned_1d")
    merge_increase(fails_1d_data, "failed_1d")

    # Helper to merge range ("values") data into a per-cell series
    def merge_series(data, series_key):
        for result in data:
            metric = result.get("metric", {})
            jail_name = metric.get("jail")
            instance_name = metric.get("instance", "unknown")

            if not jail_name or jail_name not in jails_data:
                continue
            if instance_name not in jails_data[jail_name]:
                continue

            series = [float(point[1]) for point in result.get("values", [])]
            jails_data[jail_name][instance_name][series_key] = series

    merge_series(bans_series_data, "bans_series")
    merge_series(fails_series_data, "fails_series")

    return jails_data, sorted(list(instances))


def format_increase(value, gradient_max) -> str:
    """Color-grades a windowed increase() value (1h / 1d)."""
    if value == 0:
        return f"[bright_black]{value}[/bright_black]"

    if value < 0:
        return f"[bold red]{value}[/bold red]"

    position = value / gradient_max if value > 0 else 0.0
    color = get_gradient_color(position, VALUE_GRADIENT_STOPS)
    return f"[bold {color}]{value}[/bold {color}]"


def create_inner_grid(
    bans_1h,
    bans_1d,
    fails_1h,
    fails_1d,
    bans_series=None,
    fails_series=None,
):
    """Creates a borderless Rich Grid to perfectly align sub-columns."""
    grid = Table.grid(padding=(0, 0))

    # Define exact widths for each element in the string to enforce alignment
    grid.add_column(justify="left", width=7)  # Label ("Bans:" / "Fails:")
    grid.add_column(justify="center", width=6)  # 1h Value
    grid.add_column(justify="center", width=3)  # Slash
    grid.add_column(justify="center", width=6)  # 1d Value
    grid.add_column(
        justify="left", width=SPARK_WIDTH + 1
    )  # Inline sparkline (1h trend)

    # Format colors (gradient maxes tuned per window/metric)
    bans_1h_str = format_increase(bans_1h, 10)
    bans_1d_str = format_increase(bans_1d, 50)
    fails_1h_str = format_increase(fails_1h, 100)
    fails_1d_str = format_increase(fails_1d, 1000)

    # Leading space separates the sparkline from the 1d value column
    bans_spark = " " + render_sparkline(bans_series or [])
    fails_spark = " " + render_sparkline(fails_series or [])

    # Add the rows into our mini-grid
    grid.add_row("Bans:", bans_1h_str, "/", bans_1d_str, bans_spark)
    grid.add_row("Fails:", fails_1h_str, "/", fails_1d_str, fails_spark)

    return grid


def display_matrix_table(jails_data, instances):
    """Renders the statistics in a Jail (Rows) x Nodes (Columns) matrix."""
    table = Table(
        title="Fail2Ban Statistics Matrix (1h / 1d)",
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
                bans_1h=stats["banned_1h"],
                bans_1d=stats["banned_1d"],
                fails_1h=stats["failed_1h"],
                fails_1d=stats["failed_1d"],
                bans_series=stats["bans_series"],
                fails_series=stats["fails_series"],
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
