#!/usr/bin/env python3
"""
STA Agent MCP Server — expose STA tools to VS Code Copilot Chat.

Runs as a Model Context Protocol (MCP) stdio server. Copilot Chat can call
query_timing_db, query_csv, list_available_data, list_reports, and read_report
as tools, bringing STA analysis directly into the editor.

Requires: pip install mcp duckdb anthropic
"""

import json
import os
import sys

import duckdb
from mcp.server.fastmcp import FastMCP

# Add parent dir so we can import from the agent
sys.path.insert(0, os.path.dirname(__file__))
from config import BLOCKS, DB_PATH
from agent import (
    execute_query,
    list_data,
    list_report_files,
    read_report_file,
    load_system_prompt,
    triage_timing_run as _triage_timing_run,
    export_bucket_file as _export_bucket_file,
    validate_buckets as _validate_buckets,
)

mcp = FastMCP(
    "sta-agent",
    description="AI-powered Static Timing Analysis — query timing databases, read PrimeTime reports, and analyze violations",
)

# ---------- database connection (lazy, read-only) ----------

_con = None

def _get_con():
    global _con
    if _con is None:
        if os.path.exists(DB_PATH):
            _con = duckdb.connect(DB_PATH, read_only=True)
        else:
            _con = duckdb.connect(":memory:")
    return _con


# ---------- MCP tools ----------

@mcp.tool()
def query_timing_db(sql: str, explanation: str = "") -> str:
    """Execute a SQL query against the pre-ingested STA timing DuckDB database.

    The database has a `paths` table with columns: block, run_label, mode,
    slack, clock_percentage, period, startpoint, endpoint, launch_clock,
    capture_clock, path_group, int_ext, int_ext_child, driver_partition,
    receiver_partition, levels_of_logic, num_unique_fanout, path_type.

    Args:
        sql: SQL query to execute against the paths table.
        explanation: Brief description of what this query does.
    """
    result = execute_query(_get_con(), sql)
    return json.dumps(result, default=str)


@mcp.tool()
def query_csv(sql: str, explanation: str = "") -> str:
    """Execute a SQL query against a CSV.gz file on NFS using DuckDB read_csv_auto.

    No ingest needed — reads CSV files directly. Example:
    SELECT slack, startpoint, endpoint
    FROM read_csv_auto('/nfs/.../report_summary.max.csv.gz')
    WHERE slack < 0 ORDER BY slack LIMIT 20

    Args:
        sql: SQL using read_csv_auto('/path/to/file.csv.gz').
        explanation: Brief description of what this query does.
    """
    if "read_csv_auto" not in sql.lower():
        return json.dumps({"error": "query_csv must use read_csv_auto()"})
    result = execute_query(_get_con(), sql)
    return json.dumps(result, default=str)


@mcp.tool()
def list_available_data() -> str:
    """List all blocks and runs available in the pre-ingested timing database with row counts and worst slack."""
    result = list_data(_get_con())
    return json.dumps(result, default=str)


@mcp.tool()
def list_reports(
    block: str = "",
    run_label: str = "",
    mode: str = "",
    reports_dir: str = "",
) -> str:
    """List available PrimeTime report files (.rpt.gz, .csv.gz) in a reports directory.

    Provide EITHER (block + run_label + mode) for configured blocks,
    OR (reports_dir) for any NFS directory.

    Args:
        block: Block name (e.g. d2d1) — for configured blocks.
        run_label: Run label — for configured blocks.
        mode: 'setup' or 'hold' — for configured blocks.
        reports_dir: Direct path to a reports directory on NFS.
    """
    result = list_report_files(
        block=block or None,
        run_label=run_label or None,
        mode=mode or None,
        reports_dir=reports_dir or None,
    )
    return json.dumps(result, default=str)


@mcp.tool()
def read_report(
    block: str = "",
    run_label: str = "",
    mode: str = "",
    report_name: str = "",
    file_path: str = "",
    max_lines: int = 200,
    tail: bool = False,
    grep: str = "",
    context_lines: int = 2,
) -> str:
    """Read a PrimeTime report file (.rpt.gz or .csv.gz) with head/tail/grep.

    Provide EITHER (block + run_label + mode + report_name) for configured blocks,
    OR (file_path) for any NFS file.

    Args:
        block: Block name — for configured blocks.
        run_label: Run label — for configured blocks.
        mode: 'setup' or 'hold' — for configured blocks.
        report_name: Report filename in the configured reports dir.
        file_path: Direct absolute path to a report file on NFS.
        max_lines: Maximum lines to return (default 200, max 500).
        tail: If true, read last max_lines instead of first.
        grep: Return only lines matching this regex pattern (case-insensitive).
        context_lines: Lines of context around grep matches (default 2).
    """
    result = read_report_file(
        block=block or None,
        run_label=run_label or None,
        mode=mode or None,
        report_name=report_name or None,
        max_lines=max_lines,
        tail=tail,
        grep=grep or None,
        context_lines=context_lines,
        file_path=file_path or None,
    )
    return json.dumps(result, default=str)


@mcp.tool()
def triage_timing_run(block: str = "", run_label: str = "", mode: str = "setup", csv_path: str = "") -> str:
    """Analyze all failing paths (up to 200K) in a block/run and group into triage bucket candidates.

    Groups paths by clock domains, partition crossings, path types, and logic depth.
    Returns a summary, all grouped bucket candidates (no limit), and the top 200 worst paths.
    Use this as the first step when triaging a timing run.

    Works in two modes:
    - Pre-ingested data: provide block + run_label + mode
    - Ad-hoc CSV: provide csv_path (NFS path to a .csv.gz report) + mode

    Args:
        block: Block name (e.g. d2d1) — for pre-ingested data.
        run_label: Run label (e.g. 26ww14.3) — for pre-ingested data.
        mode: 'setup' or 'hold'.
        csv_path: Path to a CSV.gz timing report on NFS — for ad-hoc triage without ingesting.
    """
    result = _triage_timing_run(
        _get_con(),
        block or None,
        run_label or None,
        mode,
        csv_path=csv_path or None,
    )
    return json.dumps(result, default=str)


@mcp.tool()
def export_bucket_file(
    block: str,
    run_label: str,
    mode: str,
    output_path: str,
    buckets: list,
) -> str:
    """Generate a timinglite-compatible bucket file from triage results.

    Each bucket should have: filters (list of timinglite filter strings like
    'LaunchClk:uclk_mem', 'StartPin:^pard2d1chnl/'), a classification
    (CLASSIF_PTECO, CLASSIF_CONSTRAINTS, or CLASSIF_FCT), and a description.
    The output bucket file can be loaded directly in Timing Lite.

    Args:
        block: Block name.
        run_label: Run label.
        mode: 'setup' or 'hold'.
        output_path: File path to write the bucket file.
        buckets: List of bucket dicts with keys: priority, filters, classification, description.
    """
    result = _export_bucket_file(buckets, output_path, block, run_label, mode)
    return json.dumps(result, default=str)


@mcp.tool()
def validate_buckets(
    mode: str,
    buckets: list,
    block: str = "",
    run_label: str = "",
    csv_path: str = "",
) -> str:
    """Validate bucket filter coverage against actual failing paths.

    Tests each bucket's regex filters against the data and reports how many paths
    each bucket matches, total unmatched (catch-all) count and percentage, and a
    sample of unmatched paths. Use after creating buckets to verify coverage is >95%.

    Args:
        mode: 'setup' or 'hold'.
        buckets: List of bucket dicts with keys: filters, classification, description.
        block: Block name (for pre-ingested data).
        run_label: Run label (for pre-ingested data).
        csv_path: Path to CSV.gz for ad-hoc mode.
    """
    con = duckdb.connect(DB_PATH, read_only=True)
    try:
        result = _validate_buckets(con, buckets, block, run_label, mode, csv_path=csv_path or None)
        return json.dumps(result, default=str)
    finally:
        con.close()


@mcp.resource("sta://blocks")
def get_blocks() -> str:
    """List all configured blocks and their runs."""
    info = {}
    for block, data in BLOCKS.items():
        info[block] = {
            "owner": data["owner"],
            "runs": [r["label"] for r in data["runs"]],
        }
    return json.dumps(info, indent=2)


@mcp.resource("sta://schema")
def get_schema() -> str:
    """Return the paths table schema for reference."""
    return """Table: paths
| Column            | Type    | Description                                          |
|-------------------|---------|------------------------------------------------------|
| block             | VARCHAR | Block name (d2d1, d2d4, memstack, uio_a_0)          |
| run_label         | VARCHAR | Run identifier (e.g. 26ww15.2)                      |
| mode              | VARCHAR | 'setup' or 'hold'                                   |
| slack             | DOUBLE  | Path slack in ps. Negative = failing.                |
| clock_percentage  | DOUBLE  | Slack as % of clock period (setup only)              |
| period            | DOUBLE  | Clock period in ps                                   |
| startpoint        | VARCHAR | Launch register/port                                 |
| endpoint          | VARCHAR | Capture register/port                                |
| launch_clock      | VARCHAR | Clock that launches data                             |
| capture_clock     | VARCHAR | Clock that captures data                             |
| path_group        | VARCHAR | Timing path group                                   |
| int_ext           | VARCHAR | 'INT' or 'EXT'                                      |
| int_ext_child     | VARCHAR | 'R2R', 'C2C', etc.                                  |
| driver_partition  | VARCHAR | Partition of the driving cell                        |
| receiver_partition| VARCHAR | Partition of the receiving cell                      |
| levels_of_logic   | INTEGER | Combinational logic levels in path                   |
| num_unique_fanout | INTEGER | Fanout count at endpoint                             |
| path_type         | VARCHAR | 'max' (setup) or 'min' (hold)                       |"""


if __name__ == "__main__":
    mcp.run()
