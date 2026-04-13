#!/usr/bin/env python3
"""
STA Agent — AI-powered STA analysis CLI.

Uses Claude (via Intel GNAI gateway) to translate natural language questions
into SQL queries against a DuckDB database of STA timing paths, then
analyzes the results.

Usage:
    python agent.py "top 10 worst setup paths in d2d1"
    python agent.py "compare d2d4 ww15.2 vs ww14.5 setup"
    python agent.py --interactive
    python agent.py --block d2d1 --run 26ww14.3 --mode setup "worst paths and suggest fixes"

Environment:
    GNAI_API_KEY        — required, your GNAI API key
    ANTHROPIC_API_KEY   — fallback if GNAI_API_KEY not set (direct Anthropic)
    INTEL_CERT_BUNDLE   — path to Intel CA bundle (auto-detected if not set)
"""

import argparse
import gzip
import json
import os
import re
import sys
import textwrap

from datetime import datetime

import anthropic
import duckdb
from rich.console import Console
from rich.markdown import Markdown
from rich.table import Table

from config import BLOCKS, DB_PATH

console = Console()

# GNAI gateway configuration
GNAI_BASE_URL = "https://gnai.intel.com/api/providers/anthropic"
GNAI_MODEL = "claude-4-5-sonnet"
DIRECT_MODEL = "claude-sonnet-4-20250514"

SYSTEM_PROMPT_PATH = os.path.join(os.path.dirname(__file__), "prompts", "system.txt")

TOOL_SCHEMA = [
    {
        "name": "query_timing_db",
        "description": "Execute a SQL query against the timing DuckDB database (pre-ingested data). Returns results as a list of rows. Use this for blocks/runs that are in the database.",
        "input_schema": {
            "type": "object",
            "properties": {
                "sql": {
                    "type": "string",
                    "description": "The SQL query to execute against the paths table."
                },
                "explanation": {
                    "type": "string",
                    "description": "Brief explanation of what this query does."
                }
            },
            "required": ["sql", "explanation"]
        }
    },
    {
        "name": "query_csv",
        "description": "Execute a SQL query against a CSV.gz file directly from NFS using DuckDB's read_csv_auto. No ingest needed. Use for ad-hoc analysis of any timing CSV on disk. Example: SELECT slack, clock_percentage, startpoint, endpoint FROM read_csv_auto('/path/to/report_summary.max.csv.gz') WHERE slack < 0 ORDER BY slack LIMIT 20",
        "input_schema": {
            "type": "object",
            "properties": {
                "sql": {
                    "type": "string",
                    "description": "SQL query using read_csv_auto('/path/to/file.csv.gz'). Can join multiple CSV files."
                },
                "explanation": {
                    "type": "string",
                    "description": "Brief explanation of what this query does."
                }
            },
            "required": ["sql", "explanation"]
        }
    },
    {
        "name": "list_available_data",
        "description": "List all blocks and runs available in the pre-ingested database with row counts.",
        "input_schema": {
            "type": "object",
            "properties": {},
        }
    },
    {
        "name": "list_reports",
        "description": "List available PrimeTime report files in a reports directory. Works with both configured blocks and ad-hoc paths. Provide EITHER (block + run_label + mode) for configured blocks, OR (reports_dir) for any NFS directory.",
        "input_schema": {
            "type": "object",
            "properties": {
                "block": {
                    "type": "string",
                    "description": "Block name (e.g., d2d1) — for configured blocks"
                },
                "run_label": {
                    "type": "string",
                    "description": "Run label — for configured blocks"
                },
                "mode": {
                    "type": "string",
                    "enum": ["setup", "hold"],
                    "description": "setup or hold — for configured blocks"
                },
                "reports_dir": {
                    "type": "string",
                    "description": "Direct path to a reports directory on NFS — for ad-hoc analysis"
                }
            },
        }
    },
    {
        "name": "read_report",
        "description": "Read a PrimeTime report file (.rpt.gz or .csv.gz). Works with both configured blocks and direct file paths. Provide EITHER (block + run_label + mode + report_name), OR (file_path) for any NFS file. Use max_lines or grep to limit output.",
        "input_schema": {
            "type": "object",
            "properties": {
                "block": {
                    "type": "string",
                    "description": "Block name — for configured blocks"
                },
                "run_label": {
                    "type": "string",
                    "description": "Run label — for configured blocks"
                },
                "mode": {
                    "type": "string",
                    "enum": ["setup", "hold"],
                    "description": "setup or hold — for configured blocks"
                },
                "report_name": {
                    "type": "string",
                    "description": "Report filename in the configured reports dir"
                },
                "file_path": {
                    "type": "string",
                    "description": "Direct absolute path to a report file on NFS — for ad-hoc analysis"
                },
                "max_lines": {
                    "type": "integer",
                    "description": "Maximum lines to return (default 200). Use to read the beginning of a report."
                },
                "tail": {
                    "type": "boolean",
                    "description": "If true, read last max_lines instead of first."
                },
                "grep": {
                    "type": "string",
                    "description": "Return only lines matching this pattern (case-insensitive regex)."
                },
                "context_lines": {
                    "type": "integer",
                    "description": "Number of lines of context around grep matches (default 2)."
                }
            },
        }
    },
    {
        "name": "triage_timing_run",
        "description": "Analyze all failing paths (up to 200K) in a block/run and group them into bucket candidates based on clock domains, partition crossings, path types, and logic depth. Returns: a summary, all grouped bucket candidates (no limit), and the top 200 worst individual paths for pattern analysis. Use this as the first step of triage. Works with either pre-ingested data (block/run_label/mode) or ad-hoc CSV files (csv_path).",
        "input_schema": {
            "type": "object",
            "properties": {
                "block": {
                    "type": "string",
                    "description": "Block name (e.g., d2d1) — for pre-ingested data"
                },
                "run_label": {
                    "type": "string",
                    "description": "Run label (e.g., 26ww14.3) — for pre-ingested data"
                },
                "mode": {
                    "type": "string",
                    "enum": ["setup", "hold"],
                    "description": "setup or hold"
                },
                "csv_path": {
                    "type": "string",
                    "description": "Path to a CSV.gz timing report on NFS — for ad-hoc triage without ingesting. If provided, block/run_label are optional labels."
                }
            },
            "required": ["mode"]
        }
    },
    {
        "name": "export_bucket_file",
        "description": "Generate a timinglite-compatible bucket file from triage results. Each bucket has filter expressions (timinglite syntax), an owner classification, and a root cause description. The bucket file can be loaded directly in Timing Lite.",
        "input_schema": {
            "type": "object",
            "properties": {
                "block": {
                    "type": "string",
                    "description": "Block name"
                },
                "run_label": {
                    "type": "string",
                    "description": "Run label"
                },
                "mode": {
                    "type": "string",
                    "enum": ["setup", "hold"],
                    "description": "setup or hold"
                },
                "output_path": {
                    "type": "string",
                    "description": "File path to write the bucket file (e.g., ./buckets/d2d1_26ww14.3_setup.bucket)"
                },
                "buckets": {
                    "type": "array",
                    "description": "List of bucket definitions",
                    "items": {
                        "type": "object",
                        "properties": {
                            "priority": {
                                "type": "integer",
                                "description": "Bucket priority (1 = highest)"
                            },
                            "filters": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Filter expressions in timinglite syntax: LaunchClk:<regex>, CaptureClk:<regex>, StartPin:<regex>, EndPin:<regex>, PercentPeriod:<comparison>"
                            },
                            "classification": {
                                "type": "string",
                                "description": "Owner: CLASSIF_PTECO (auto-fix), CLASSIF_CONSTRAINTS (SDC issues), or CLASSIF_FCT (manual RTL/floorplan)"
                            },
                            "description": {
                                "type": "string",
                                "description": "Root cause analysis and recommended fix action"
                            }
                        },
                        "required": ["filters", "classification", "description"]
                    }
                }
            },
            "required": ["block", "run_label", "mode", "output_path", "buckets"]
        }
    },
]


def load_system_prompt(reports_dir=None):
    """Load the system prompt and append available data context."""
    with open(SYSTEM_PROMPT_PATH, "r") as f:
        prompt = f.read()

    # Append available blocks/runs from config
    context = "\n\n## Available Data\n"
    for block, data in BLOCKS.items():
        runs = ", ".join(r["label"] for r in data["runs"])
        context += f"- **{block}** (owner: {data['owner']}): {runs}\n"

    # Append ad-hoc reports directory if provided
    if reports_dir:
        context += f"\n## Ad-hoc Reports Directory\n"
        context += f"The user has pointed to: `{reports_dir}`\n"
        context += f"Use `list_reports` with reports_dir to discover available files.\n"
        context += f"Use `query_csv` with read_csv_auto() to query CSV files directly.\n"
        context += f"Use `read_report` with file_path to read report files directly.\n"
        # List CSV files for convenience
        if os.path.isdir(reports_dir):
            csvs = [f for f in os.listdir(reports_dir) if f.endswith('.csv.gz') or f.endswith('.csv')]
            if csvs:
                context += f"\nCSV files available for query_csv:\n"
                for c in sorted(csvs):
                    context += f"- `{os.path.join(reports_dir, c)}`\n"

    return prompt + context


def execute_query(con, sql):
    """Execute SQL and return formatted results."""
    try:
        result = con.execute(sql)
        columns = [desc[0] for desc in result.description]
        rows = result.fetchall()
        return {"columns": columns, "rows": [list(r) for r in rows], "count": len(rows)}
    except Exception as e:
        return {"error": str(e)}


def list_data(con):
    """List available data in the database."""
    try:
        result = con.execute("""
            SELECT block, run_label, mode, COUNT(*) as path_count,
                   ROUND(MIN(slack), 1) as worst_slack,
                   ROUND(AVG(slack), 1) as avg_slack
            FROM paths
            GROUP BY block, run_label, mode
            ORDER BY block, run_label, mode
        """)
        columns = [desc[0] for desc in result.description]
        rows = result.fetchall()
        return {"columns": columns, "rows": [list(r) for r in rows], "count": len(rows)}
    except Exception as e:
        return {"error": str(e)}


def display_result(result):
    """Display query results as a rich table."""
    if "error" in result:
        console.print(f"[red]SQL Error: {result['error']}[/red]")
        return

    if not result["rows"]:
        console.print("[dim]No results.[/dim]")
        return

    table = Table(show_lines=False, padding=(0, 1))
    for col in result["columns"]:
        table.add_column(col, style="cyan" if col in ("block", "run_label") else None)

    for row in result["rows"][:50]:  # Cap display at 50 rows
        table.add_row(*[str(v) if v is not None else "" for v in row])

    if result["count"] > 50:
        console.print(f"[dim](Showing 50 of {result['count']} rows)[/dim]")

    console.print(table)


def get_reports_dir(block, run_label, mode):
    """Derive the reports directory from config CSV paths."""
    if block not in BLOCKS:
        return None
    for run in BLOCKS[block]["runs"]:
        if run["label"] == run_label:
            csv_key = "setup_csv" if mode == "setup" else "hold_csv"
            csv_path = run.get(csv_key, "")
            if csv_path:
                return os.path.dirname(csv_path)
    return None


def list_report_files(block=None, run_label=None, mode=None, reports_dir=None):
    """List .rpt.gz files in the reports directory."""
    if reports_dir:
        rdir = reports_dir
    else:
        rdir = get_reports_dir(block, run_label, mode)
    if not rdir:
        return {"error": f"No config found for {block}/{run_label}/{mode}"}
    if not os.path.isdir(rdir):
        return {"error": f"Directory not found: {rdir}"}

    files = []
    for f in sorted(os.listdir(rdir)):
        if f.endswith('.rpt.gz') or f.endswith('.rpt') or f.endswith('.csv.gz') or f.endswith('.csv'):
            fpath = os.path.join(rdir, f)
            size = os.path.getsize(fpath)
            # Show human-readable size
            if size > 1024 * 1024:
                size_str = f"{size / (1024*1024):.1f}MB"
            elif size > 1024:
                size_str = f"{size / 1024:.1f}KB"
            else:
                size_str = f"{size}B"
            files.append({"name": f, "size": size_str})

    return {"directory": rdir, "files": files, "count": len(files)}


def read_report_file(block=None, run_label=None, mode=None, report_name=None,
                     max_lines=200, tail=False, grep=None, context_lines=2,
                     file_path=None):
    """Read a .rpt.gz file with head/tail/grep support."""
    if file_path:
        # Direct file path mode — validate it's under /nfs/
        if not file_path.startswith('/nfs/'):
            return {"error": "file_path must be an absolute NFS path starting with /nfs/"}
        fpath = file_path
    else:
        reports_dir = get_reports_dir(block, run_label, mode)
        if not reports_dir:
            return {"error": f"No config found for {block}/{run_label}/{mode}"}
        # Security: prevent path traversal
        if '..' in report_name or '/' in report_name:
            return {"error": "Invalid report name"}
        fpath = os.path.join(reports_dir, report_name)

    if not os.path.isfile(fpath):
        return {"error": f"File not found: {fpath}"}

    max_lines = min(max_lines or 200, 500)  # Cap at 500 lines

    try:
        open_fn = gzip.open if fpath.endswith('.gz') else open
        with open_fn(fpath, 'rt', errors='replace') as f:
            all_lines = f.readlines()
    except Exception as e:
        return {"error": f"Failed to read: {e}"}

    total_lines = len(all_lines)

    if grep:
        # Grep mode: find matching lines with context
        try:
            pattern = re.compile(grep, re.IGNORECASE)
        except re.error as e:
            return {"error": f"Invalid regex: {e}"}

        matches = []
        match_indices = set()
        for i, line in enumerate(all_lines):
            if pattern.search(line):
                match_indices.add(i)

        # Add context lines
        expanded = set()
        for idx in match_indices:
            for c in range(max(0, idx - context_lines), min(total_lines, idx + context_lines + 1)):
                expanded.add(c)

        result_lines = []
        prev_idx = -2
        for idx in sorted(expanded):
            if idx > prev_idx + 1:
                result_lines.append("---")
            result_lines.append(f"{idx+1}: {all_lines[idx].rstrip()}")
            prev_idx = idx
            if len(result_lines) >= max_lines:
                break

        return {
            "total_lines": total_lines,
            "matches": len(match_indices),
            "content": "\n".join(result_lines),
        }
    elif tail:
        lines = all_lines[-max_lines:]
        start = total_lines - len(lines) + 1
        content = "\n".join(f"{start+i}: {l.rstrip()}" for i, l in enumerate(lines))
        return {"total_lines": total_lines, "showing": f"last {len(lines)}", "content": content}
    else:
        lines = all_lines[:max_lines]
        content = "\n".join(f"{i+1}: {l.rstrip()}" for i, l in enumerate(lines))
        truncated = total_lines > max_lines
        return {
            "total_lines": total_lines,
            "showing": f"first {len(lines)}",
            "truncated": truncated,
            "content": content,
        }


def triage_timing_run(con, block, run_label, mode, csv_path=None):
    """Analyze failing paths and group into triage bucket candidates.

    Works in two modes:
    - Ingested data: queries the paths table (block/run_label/mode)
    - Ad-hoc CSV: queries a CSV.gz file directly via read_csv_auto (csv_path)
    """
    try:
        if csv_path:
            # Ad-hoc mode: query CSV directly
            source = f"read_csv_auto('{csv_path}')"
            where = "slack < 0"
            params = []
        else:
            # Ingested mode: query paths table
            source = "paths"
            where = "block = ? AND run_label = ? AND mode = ? AND slack < 0"
            params = [block, run_label, mode]

        # Overall summary
        summary = con.execute(f"""
            SELECT
                COUNT(*) as total_failing,
                ROUND(MIN(slack), 1) as worst_slack,
                ROUND(AVG(slack), 1) as avg_slack,
                COUNT(DISTINCT launch_clock || ' -> ' || capture_clock) as clock_domain_pairs,
                COUNT(DISTINCT driver_partition || ' -> ' || receiver_partition) as partition_crossings
            FROM {source}
            WHERE {where}
        """, params)
        sum_cols = [d[0] for d in summary.description]
        sum_rows = [list(r) for r in summary.fetchall()]

        # Bucket candidates: group by key dimensions
        groups = con.execute(f"""
            SELECT
                launch_clock,
                capture_clock,
                int_ext,
                int_ext_child,
                driver_partition,
                receiver_partition,
                COUNT(*) as path_count,
                ROUND(MIN(slack), 1) as worst_slack,
                ROUND(AVG(slack), 1) as avg_slack,
                ROUND(MIN(clock_percentage), 1) as worst_clock_pct,
                ROUND(AVG(levels_of_logic), 0) as avg_levels_of_logic,
                MIN(levels_of_logic) as min_lol,
                MAX(levels_of_logic) as max_lol
            FROM {source}
            WHERE {where}
            GROUP BY launch_clock, capture_clock, int_ext, int_ext_child,
                     driver_partition, receiver_partition
            ORDER BY path_count DESC
        """, params)
        grp_cols = [d[0] for d in groups.description]
        grp_rows = [list(r) for r in groups.fetchall()]

        # Top 200 worst paths with full detail for pattern analysis
        worst = con.execute(f"""
            SELECT
                slack, clock_percentage, launch_clock, capture_clock,
                int_ext, int_ext_child, driver_partition, receiver_partition,
                levels_of_logic, startpoint, endpoint
            FROM {source}
            WHERE {where}
            ORDER BY slack ASC
            LIMIT 200
        """, params)
        worst_cols = [d[0] for d in worst.description]
        worst_rows = [list(r) for r in worst.fetchall()]

        return {
            "block": block or os.path.basename(csv_path),
            "run_label": run_label or csv_path,
            "mode": mode,
            "summary": {"columns": sum_cols, "rows": sum_rows},
            "bucket_candidates": {"columns": grp_cols, "rows": grp_rows, "count": len(grp_rows)},
            "worst_paths": {"columns": worst_cols, "rows": worst_rows, "count": len(worst_rows)},
        }
    except Exception as e:
        return {"error": str(e)}


def _sanitize_filter_regex(filter_str):
    """Fix common regex issues in timinglite filter values.

    Timinglite uses re2 which rejects bare * (no preceding char).
    Convert glob-style patterns to valid regex.
    """
    # Split on : to get column:value
    if ':' not in filter_str:
        return filter_str
    col, val = filter_str.split(':', 1)

    # Fix bare * at start of value (glob) → .* (regex)
    if val.startswith('*'):
        val = '.' + val
    # Fix *something → .*something anywhere after start
    val = re.sub(r'(?<!\.)\*', '.*', val)
    # Fix ** → .* (double-glob)
    val = val.replace('.**', '.*')
    # Remove trailing bare * that became .* redundantly after .*
    val = re.sub(r'(\.\*)+', '.*', val)

    return f"{col}:{val}"


def export_bucket_file(buckets, output_path, block, run_label, mode):
    """Write a timinglite-compatible bucket file.

    Args:
        buckets: list of dicts with keys: priority, filters, classification, description
        output_path: path to write the bucket file
        block: block name
        run_label: run label
        mode: setup or hold
    """
    lines = [
        f"# STA Agent Auto-Triage Bucket File",
        f"# Block: {block}  Run: {run_label}  Mode: {mode}",
        f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"#",
        f"# Load in Timing Lite: timinglite.py --bucket <this_file> <report>",
        f"#",
    ]

    path_type = "max" if mode == "setup" else "min"

    for bucket in buckets:
        priority = bucket.get("priority", 1)
        raw_filters = bucket.get("filters", [])
        # Remove any PathType filters provided by Claude (we add it ourselves)
        raw_filters = [f for f in raw_filters if not f.startswith("PathType:")]
        filters = [f"PathType:{path_type}"] + [_sanitize_filter_regex(f) for f in raw_filters]
        classification = bucket.get("classification", "")
        description = bucket.get("description", "").replace("\n", " ")

        filter_str = "&&".join(filters)
        lines.append(f"{priority} {filter_str} {classification} {description}")

    content = "\n".join(lines) + "\n"

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, 'w') as f:
        f.write(content)

    return {
        "path": os.path.abspath(output_path),
        "bucket_count": len(buckets),
        "content": content,
    }


def handle_tool_call(con, tool_name, tool_input):
    """Execute a tool call and return the result."""
    if tool_name == "query_timing_db":
        sql = tool_input["sql"]
        explanation = tool_input.get("explanation", "")
        console.print(f"\n[dim]Query: {explanation}[/dim]")
        console.print(f"[dim]{sql}[/dim]\n")
        result = execute_query(con, sql)
        display_result(result)
        return json.dumps(result, default=str)

    elif tool_name == "query_csv":
        sql = tool_input["sql"]
        explanation = tool_input.get("explanation", "")
        console.print(f"\n[dim]CSV Query: {explanation}[/dim]")
        console.print(f"[dim]{sql}[/dim]\n")
        # Security: only allow read_csv_auto on /nfs/ paths
        if 'read_csv_auto' not in sql.lower():
            return json.dumps({"error": "query_csv must use read_csv_auto()"})
        result = execute_query(con, sql)
        display_result(result)
        return json.dumps(result, default=str)

    elif tool_name == "list_available_data":
        result = list_data(con)
        display_result(result)
        return json.dumps(result, default=str)

    elif tool_name == "list_reports":
        block = tool_input.get("block")
        run_label = tool_input.get("run_label")
        mode = tool_input.get("mode")
        reports_dir = tool_input.get("reports_dir")
        label = reports_dir or f"{block}/{run_label} ({mode})"
        console.print(f"\n[dim]Listing reports: {label}[/dim]\n")
        result = list_report_files(block, run_label, mode, reports_dir)
        if "error" not in result:
            for f in result["files"]:
                console.print(f"  [dim]{f['size']:>8s}  {f['name']}[/dim]")
            console.print(f"  [dim]({result['count']} files)[/dim]")
        else:
            console.print(f"[red]{result['error']}[/red]")
        return json.dumps(result, default=str)

    elif tool_name == "read_report":
        block = tool_input.get("block")
        run_label = tool_input.get("run_label")
        mode = tool_input.get("mode")
        report_name = tool_input.get("report_name")
        file_path = tool_input.get("file_path")
        max_lines = tool_input.get("max_lines", 200)
        tail = tool_input.get("tail", False)
        grep_pat = tool_input.get("grep")
        context_lines = tool_input.get("context_lines", 2)
        label = file_path or f"{block}/{run_label}/{report_name}"
        if grep_pat:
            console.print(f"\n[dim]Reading {label} (grep: {grep_pat})[/dim]\n")
        elif tail:
            console.print(f"\n[dim]Reading {label} (tail {max_lines})[/dim]\n")
        else:
            console.print(f"\n[dim]Reading {label} (head {max_lines})[/dim]\n")
        result = read_report_file(block, run_label, mode, report_name,
                                  max_lines, tail, grep_pat, context_lines,
                                  file_path=file_path)
        if "error" in result:
            console.print(f"[red]{result['error']}[/red]")
        else:
            console.print(f"[dim]({result['total_lines']} total lines)[/dim]")
        return json.dumps(result, default=str)

    elif tool_name == "triage_timing_run":
        block = tool_input.get("block")
        run_label = tool_input.get("run_label")
        mode = tool_input["mode"]
        csv_path = tool_input.get("csv_path")
        label = csv_path or f"{block}/{run_label}"
        console.print(f"\n[dim]Triaging {label} ({mode})...[/dim]\n")
        result = triage_timing_run(con, block, run_label, mode, csv_path=csv_path)
        if "error" not in result:
            summary = result["summary"]["rows"][0] if result["summary"]["rows"] else []
            if summary:
                console.print(f"  [bold]{summary[0]}[/bold] failing paths, worst slack: [red]{summary[1]}ps[/red]")
                console.print(f"  {summary[3]} clock domain pairs, {summary[4]} partition crossings")
            console.print(f"  {result['bucket_candidates']['count']} bucket candidates identified\n")
        else:
            console.print(f"[red]{result['error']}[/red]")
        return json.dumps(result, default=str)

    elif tool_name == "export_bucket_file":
        block = tool_input["block"]
        run_label = tool_input["run_label"]
        mode = tool_input["mode"]
        output_path = tool_input["output_path"]
        buckets = tool_input["buckets"]
        console.print(f"\n[dim]Generating bucket file: {output_path}[/dim]\n")
        result = export_bucket_file(buckets, output_path, block, run_label, mode)
        console.print(f"  [bold green]Wrote {result['bucket_count']} buckets[/bold green] to {result['path']}")
        console.print(f"  [dim]Load in Timing Lite: timinglite.py --bucket {result['path']} <report>[/dim]\n")
        return json.dumps(result, default=str)

    return json.dumps({"error": f"Unknown tool: {tool_name}"})


def run_agent(con, client, question, block=None, run=None, mode=None, model=DIRECT_MODEL,
              reports_dir=None, messages=None, max_tokens=4096):
    """Run the agent loop: question → tool calls → analysis.
    
    If messages is provided, appends to existing conversation (for follow-ups).
    Returns the updated messages list for conversation continuity.
    """

    # Build the user message with optional context
    user_msg = question
    if not messages:
        # First question — add context
        if block:
            user_msg += f"\n\nContext: block={block}"
        if run:
            user_msg += f", run={run}"
        if mode:
            user_msg += f", mode={mode}"
        if reports_dir:
            user_msg += f"\n\nReports directory: {reports_dir}"

    system_prompt = load_system_prompt(reports_dir=reports_dir)

    if messages is None:
        messages = []
    messages.append({"role": "user", "content": user_msg})

    console.print(f"\n[bold]Question:[/bold] {question}\n")

    # Agent loop — allow multiple tool calls
    for _ in range(20):  # safety limit
        response = client.messages.create(
            model=model,
            max_tokens=max_tokens,
            system=system_prompt,
            tools=TOOL_SCHEMA,
            messages=messages,
        )

        # Process response content blocks
        tool_results = []
        text_parts = []

        for block_content in response.content:
            if block_content.type == "text":
                text_parts.append(block_content.text)
            elif block_content.type == "tool_use":
                result = handle_tool_call(con, block_content.name, block_content.input)
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": block_content.id,
                    "content": result,
                })

        # If there was text output, display it
        if text_parts:
            console.print()
            for text in text_parts:
                console.print(Markdown(text))

        # If stop_reason is end_turn, we're done
        if response.stop_reason == "end_turn":
            messages.append({"role": "assistant", "content": response.content})
            break

        # If there were tool calls, add the assistant response and tool results
        if tool_results:
            messages.append({"role": "assistant", "content": response.content})
            messages.append({"role": "user", "content": tool_results})
        else:
            messages.append({"role": "assistant", "content": response.content})
            break

    console.print()
    return messages


def interactive_mode(con, client, model=DIRECT_MODEL, reports_dir=None):
    """Interactive REPL mode with conversation history."""
    console.print("[bold]STA Agent[/bold] — Interactive Mode")
    console.print("Type your question, or 'quit' to exit.")
    console.print("[dim]Follow-up questions remember previous context. Type 'reset' to clear history.[/dim]\n")

    messages = None  # Will be initialized on first question

    while True:
        try:
            question = console.input("[bold green]> [/bold green]").strip()
        except (EOFError, KeyboardInterrupt):
            break

        if not question or question.lower() in ("quit", "exit", "q"):
            break

        if question.lower() == "reset":
            messages = None
            console.print("[dim]Conversation history cleared.[/dim]\n")
            continue

        messages = run_agent(con, client, question, model=model,
                             reports_dir=reports_dir, messages=messages)


def main():
    parser = argparse.ArgumentParser(
        description="STA Agent — AI-powered timing analysis",
        epilog="Examples:\n"
               "  python agent.py 'top 10 worst setup paths in d2d1'\n"
               "  python agent.py --reports-dir /path/to/reports 'analyze worst setup paths'\n"
               "  python agent.py --triage -b d2d1 -r 26ww14.3 -m setup\n"
               "  python agent.py -i\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("question", nargs="?", help="Question to ask (or use --interactive)")
    parser.add_argument("--interactive", "-i", action="store_true", help="Interactive mode")
    parser.add_argument("--block", "-b", help="Focus on a specific block")
    parser.add_argument("--run", "-r", help="Focus on a specific run")
    parser.add_argument("--mode", "-m", choices=["setup", "hold"], help="Focus on setup or hold")
    parser.add_argument("--reports-dir", help="Path to a sta_pt reports directory (ad-hoc mode, no ingest needed)")
    parser.add_argument("--triage", action="store_true",
                        help="Triage mode: auto-bucket failing paths and generate a timinglite bucket file")
    parser.add_argument("--output", "-o", help="Output path for bucket file (default: ./buckets/<block>_<run>_<mode>.bucket)")
    parser.add_argument("--db", default=DB_PATH, help=f"DuckDB path (default: {DB_PATH})")
    args = parser.parse_args()

    # Check API key — prefer GNAI, fallback to direct Anthropic
    gnai_key = os.environ.get("GNAI_API_KEY")
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    use_gnai = False

    if gnai_key:
        api_key = gnai_key
        use_gnai = True
    elif not api_key:
        console.print("[red]Error: No API key found.[/red]")
        console.print("Set GNAI_API_KEY (Intel GNAI) or ANTHROPIC_API_KEY (direct).")
        console.print("  csh:  setenv GNAI_API_KEY your-key-here")
        console.print("  bash: export GNAI_API_KEY=your-key-here")
        sys.exit(1)

    # Connect to DuckDB — in-memory if no pre-built DB exists (ad-hoc mode)
    if os.path.exists(args.db):
        con = duckdb.connect(args.db, read_only=True)
        console.print(f"[dim]Database: {args.db}[/dim]")
    else:
        con = duckdb.connect(":memory:")
        if not args.reports_dir:
            console.print("[yellow]No pre-built database found. Use --reports-dir for ad-hoc analysis,[/yellow]")
            console.print("[yellow]or run `python ingest.py` to build the database.[/yellow]")

    if use_gnai:
        client = anthropic.Anthropic(
            base_url=GNAI_BASE_URL,
            auth_token=api_key,
        )
        model = GNAI_MODEL
        console.print("[dim]Using Intel GNAI gateway[/dim]")
    else:
        client = anthropic.Anthropic(api_key=api_key)
        model = DIRECT_MODEL
        console.print("[dim]Using direct Anthropic API[/dim]")

    try:
        if args.triage:
            if not args.mode:
                console.print("[red]--triage requires --mode (setup or hold)[/red]")
                sys.exit(1)
            # Determine CSV path for ad-hoc triage
            csv_path = None
            if args.reports_dir:
                # Find the matching CSV in the reports dir
                suffix = f"report_summary.{'max' if args.mode == 'setup' else 'min'}.csv.gz"
                if os.path.isdir(args.reports_dir):
                    for f in os.listdir(args.reports_dir):
                        if f.endswith(suffix):
                            csv_path = os.path.join(args.reports_dir, f)
                            break
                if not csv_path:
                    # Try using reports_dir as a direct file path
                    if os.path.isfile(args.reports_dir):
                        csv_path = args.reports_dir
                    else:
                        console.print(f"[red]No *{suffix} found in {args.reports_dir}[/red]")
                        sys.exit(1)
            elif not args.block or not args.run:
                console.print("[red]--triage requires either (--block + --run) or --reports-dir[/red]")
                sys.exit(1)

            block_label = args.block or os.path.basename(csv_path or 'unknown')
            run_label = args.run or csv_path or 'ad-hoc'
            output_path = args.output or f"./buckets/{block_label}_{args.mode}.bucket"

            csv_instruction = ""
            if csv_path:
                csv_instruction = f"\nUse csv_path='{csv_path}' when calling triage_timing_run (ad-hoc mode, no ingest needed).\n"

            triage_question = (
                f"Triage all failing {args.mode} paths in block '{block_label}', run '{run_label}'.\n"
                f"{csv_instruction}\n"
                f"Follow this workflow:\n"
                f"1. Call triage_timing_run to get bucket candidates and worst paths.\n"
                f"2. Analyze the worst 200 paths in detail — look at startpoint/endpoint hierarchical\n"
                f"   patterns (common prefixes like ^pard2d1chnl/.*, PHY blocks, HIP cells, specific IPs).\n"
                f"   Use query_timing_db to drill into large groups and discover sub-patterns.\n"
                f"3. For EACH large bucket candidate group, use query_timing_db to find:\n"
                f"   - Common startpoint/endpoint prefixes (GROUP BY SUBSTRING patterns)\n"
                f"   - HIP/PHY-related paths (large cell arc delays, PHY in hierarchy name)\n"
                f"   - Paths with unrealistic windows or constraint issues\n"
                f"   - Cross-partition paths with placement/distance issues\n"
                f"   The number of final buckets is determined by the data.\n"
                f"4. Classify each bucket using the IRIS rule categories in the system prompt:\n"
                f"   - IOC (IO constraint issues): negative windows, IO delay problems\n"
                f"   - ECO (PTECO fixable): ONLY for violations <2% of window\n"
                f"   - CON (basic constraint): window issues, clock group problems, missing exceptions\n"
                f"   - FTC (feedthrough): missing or unbuffered feedthroughs\n"
                f"   - HRP (hardrock): HIP/PHY arc delay issues, high distance, high logic depth\n"
                f"   - MOP (manual fix): long nets, crosstalk, clock DRC, overbuffering, routing\n"
                f"   - SKW (skew fix): clock skew issues, derate problems\n"
                f"   - MSC (misc/untriaged): catch-all for remaining paths\n"
                f"5. For each bucket:\n"
                f"   - Owner: CLASSIF_PTECO, CLASSIF_CONSTRAINTS, or CLASSIF_FCT\n"
                f"   - Filters: MUST include StartPin and/or EndPin regex, not just clock groups.\n"
                f"     Do NOT include PathType in filters — it is added automatically.\n"
                f"   - Map to the closest IRIS rule ID (e.g., HRP-002, IOC-004, ECO-003) in description.\n"
                f"   - Specific root cause and recommended fix action.\n"
                f"6. Every failing path must be in a bucket. Add a catch-all bucket (MSC-003 Untriaged)\n"
                f"   at the end for any remaining unmatched paths.\n"
                f"7. Call export_bucket_file to write the bucket file to: {output_path}\n"
                f"8. Print a triage summary: each bucket's IRIS category, owner, path count, worst slack, action."
            )
            run_agent(con, client, triage_question, args.block, args.run, args.mode,
                      model=model, reports_dir=args.reports_dir, max_tokens=32768)
            # Post-triage check: did the bucket file get created?
            if os.path.isfile(output_path):
                console.print(f"\n[bold green]\u2713 Bucket file written:[/bold green] {os.path.abspath(output_path)}")
                console.print(f"[dim]  Load in Timing Lite: timinglite.py --bucket {os.path.abspath(output_path)} <report>[/dim]")
            else:
                console.print(f"\n[bold yellow]\u26a0 Bucket file was NOT created at: {output_path}[/bold yellow]")
                console.print("[yellow]  The agent may have run out of tokens before reaching the export step.[/yellow]")
                console.print("[yellow]  Try re-running, or use interactive mode to complete the export.[/yellow]")
        elif args.interactive:
            interactive_mode(con, client, model, reports_dir=args.reports_dir)
        elif args.question:
            run_agent(con, client, args.question, args.block, args.run, args.mode,
                      model=model, reports_dir=args.reports_dir)
        else:
            parser.print_help()
    finally:
        con.close()


if __name__ == "__main__":
    main()
