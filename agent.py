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
        "description": "Analyze all failing paths and return pre-built buckets plus summarized data for LLM classification. Returns: (1) auto_buckets — partition internals (PO_INT) and PTECO (<2% window) already bucketed, include as-is; (2) remaining_c2c_ext — C2C/EXT path groups, startpoint/endpoint prefix counts, and worst paths for you to classify into buckets. Do NOT call extra query_timing_db for drill-down — the data is pre-summarized.",
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
    {
        "name": "validate_buckets",
        "description": "Test bucket filter coverage against actual failing paths. For each bucket, runs its regex filters as SQL against the data and counts how many paths match. Returns per-bucket match counts, total unmatched (catch-all) count and percentage, and a sample of 50 unmatched paths for pattern analysis. Use this AFTER creating buckets to verify coverage, then create additional buckets from the unmatched sample. Repeat until unmatched < 5%.",
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
                "csv_path": {
                    "type": "string",
                    "description": "Path to CSV.gz for ad-hoc mode"
                },
                "buckets": {
                    "type": "array",
                    "description": "List of bucket definitions (same format as export_bucket_file)",
                    "items": {
                        "type": "object",
                        "properties": {
                            "filters": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Filter expressions: StartPin:<regex>, EndPin:<regex>, LaunchClk:<regex>, etc."
                            },
                            "classification": {
                                "type": "string",
                                "description": "Owner classification"
                            },
                            "description": {
                                "type": "string",
                                "description": "Bucket description"
                            }
                        },
                        "required": ["filters", "classification"]
                    }
                }
            },
            "required": ["mode", "buckets"]
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


def _classify_bucket(worst_pct, avg_pct, avg_lol, worst_slack, launch_clk, capture_clk):
    """IRIS waterfall heuristic for auto-classifying a bucket.

    Uses clock_percentage when available, falls back to slack/lol/clock-domain.
    """
    # Stage 1: Constraints check (clock_percentage > 100% means over-constrained)
    if worst_pct is not None and worst_pct > 100:
        return "CLASSIF_CONSTRAINTS"
    # Cross-domain paths with scan clocks → likely constraints
    if launch_clk and capture_clk and launch_clk != capture_clk:
        scan_keywords = ("scan", "fscan", "ctf", "ovrd", "jtag", "bist", "atpg")
        lclk_lower = launch_clk.lower()
        cclk_lower = capture_clk.lower()
        if any(k in lclk_lower or k in cclk_lower for k in scan_keywords):
            return "CLASSIF_CONSTRAINTS"

    # Stage 2: Optimization window (2-30% of period)
    if avg_pct is not None and 0 < avg_pct <= 30:
        return "CLASSIF_PO_OPT"

    # Stage 3: High logic depth → HRP (pipeline restructure opportunity)
    if avg_lol is not None and avg_lol >= 30:
        return "CLASSIF_FCT"  # HRP-001: high register-to-register path depth

    # Stage 4: Moderate slack → optimization candidate
    if worst_slack is not None and avg_pct is None:
        # No clock_percentage: use absolute slack as proxy
        if worst_slack > -50:
            return "CLASSIF_PO_OPT"  # Small slack → likely optimizable
        elif avg_lol is not None and avg_lol >= 20:
            return "CLASSIF_FCT"  # Moderate depth + large slack
        else:
            return "CLASSIF_PO_OPT"  # Default to PO optimization

    # Default
    return "CLASSIF_PO_OPT"


def triage_timing_run(con, block, run_label, mode, csv_path=None):
    """Analyze failing paths and group into triage bucket candidates.

    Works in two modes:
    - Ingested data: queries the paths table (block/run_label/mode)
    - Ad-hoc CSV: queries a CSV.gz file directly via read_csv_auto (csv_path)

    For large runs (100K+ paths), auto-buckets the obvious categories in Python
    (partition internals → PO_INT, PTECO candidates → PTECO) and returns only
    summarized C2C/EXT data for the LLM to classify.
    """
    try:
        if csv_path:
            # Ad-hoc mode: normalize CSV column names to our standard schema
            source = _csv_source_with_aliases(con, csv_path)
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
        total_failing = sum_rows[0][0] if sum_rows else 0

        # ── Auto-bucket 1: Partition internals → CLASSIF_PO_INT ──
        # Use int_ext='INT' AND int_ext_child='INT' as the reliable indicator.
        # Derive partition name from the common startpoint prefix (first path component before /).
        # Never rely solely on driver_partition/receiver_partition — they may be NULL in raw CSVs.
        # Sub-group PO_INT by (partition, clock pair, startpoint prefix, endpoint prefix) for useful triage.
        po_int = con.execute(f"""
            SELECT
                COALESCE(
                    driver_partition,
                    CASE WHEN POSITION('/' IN startpoint) > 0
                         THEN SUBSTRING(startpoint, 1, POSITION('/' IN startpoint) - 1)
                         ELSE 'unknown'
                    END
                ) as partition,
                launch_clock, capture_clock,
                CASE WHEN POSITION('/' IN startpoint) > 0
                     THEN SUBSTRING(startpoint, 1, POSITION('/' IN startpoint) - 1)
                     ELSE startpoint
                END as sp_prefix,
                CASE WHEN POSITION('/' IN endpoint) > 0
                     THEN SUBSTRING(endpoint, 1, POSITION('/' IN endpoint) - 1)
                     ELSE endpoint
                END as ep_prefix,
                COUNT(*) as path_count,
                ROUND(MIN(slack), 1) as worst_slack,
                ROUND(AVG(slack), 1) as avg_slack,
                ROUND(MIN(clock_percentage), 1) as worst_clock_pct,
                ROUND(AVG(clock_percentage), 1) as avg_clock_pct,
                ROUND(AVG(levels_of_logic), 0) as avg_lol
            FROM {source}
            WHERE {where}
              AND int_ext = 'INT'
              AND (int_ext_child = 'INT' OR int_ext_child IS NULL)
            GROUP BY partition, launch_clock, capture_clock, sp_prefix, ep_prefix
            ORDER BY path_count DESC
        """, params)
        po_int_buckets = []
        po_int_total = 0
        po_int_idx = 0
        for row in po_int.fetchall():
            part_name, lclk, cclk, sp, ep, count, worst_s, avg_s, worst_pct, avg_pct, avg_lol = row
            if not part_name or part_name == 'unknown':
                continue
            po_int_total += count
            po_int_idx += 1
            filters = []
            if lclk:
                filters.append(f"LaunchClk:{lclk}")
            if cclk:
                filters.append(f"CaptureClk:{cclk}")
            if sp:
                filters.append(f"StartPin:^{sp}.*")
            if ep:
                filters.append(f"EndPin:^{ep}.*")

            # Pre-classify based on stats (IRIS waterfall heuristic)
            classif = _classify_bucket(worst_pct, avg_pct, avg_lol, worst_s, lclk, cclk)

            pct_str = f"{worst_pct}%w" if worst_pct is not None else "N/A"
            avg_pct_str = f"{avg_pct}%w" if avg_pct is not None else "N/A"
            desc = (f"PO_INT {part_name}: {lclk}->{cclk} {sp}->{ep} "
                    f"({count} paths, worst {worst_s}ps/{pct_str}, avg {avg_s}ps/{avg_pct_str}, "
                    f"avg_lol={avg_lol})")
            po_int_buckets.append({
                "priority": po_int_idx,
                "filters": filters,
                "classification": classif,
                "description": desc,
                "auto": True,
                "path_count": count,
                "worst_slack": worst_s,
                "avg_clock_pct": avg_pct,
                "worst_clock_pct": worst_pct,
            })

        # ── Auto-bucket 2: PTECO candidates (clock_percentage < 2, NOT internal) ──
        pteco = con.execute(f"""
            SELECT
                launch_clock, capture_clock,
                driver_partition, receiver_partition,
                COUNT(*) as path_count,
                ROUND(MIN(slack), 1) as worst_slack,
                ROUND(MIN(clock_percentage), 1) as worst_clock_pct
            FROM {source}
            WHERE {where}
              AND clock_percentage < 2
              AND NOT (int_ext = 'INT' AND (int_ext_child = 'INT' OR int_ext_child IS NULL))
            GROUP BY launch_clock, capture_clock, driver_partition, receiver_partition
            ORDER BY path_count DESC
        """, params)
        pteco_buckets = []
        pteco_total = 0
        pteco_idx = po_int_idx  # Continue priority numbering after PO_INT
        for row in pteco.fetchall():
            lclk, cclk, dpart, rpart, count, worst_s, worst_pct = row
            pteco_total += count
            pteco_idx += 1
            desc = f"PTECO: {lclk}->{cclk} {dpart}->{rpart} ({count} paths, worst {worst_s}ps, {worst_pct}% window)"
            filters = [f"LaunchClk:{lclk}", f"CaptureClk:{cclk}"]
            if dpart:
                filters.append(f"StartPin:^{dpart}.*")
            if rpart:
                filters.append(f"EndPin:^{rpart}.*")
            pteco_buckets.append({
                "priority": pteco_idx,
                "filters": filters,
                "classification": "CLASSIF_PTECO",
                "description": desc,
                "auto": True,
                "path_count": count,
            })

        # ── Remaining C2C/EXT paths: auto-bucket by (clock pair, startpoint prefix) ──
        # Exclude internals and PTECO — everything left is C2C/EXT for STO triage
        remaining_where = (f"{where}"
            f" AND clock_percentage >= 2"
            f" AND NOT (int_ext = 'INT' AND (int_ext_child = 'INT' OR int_ext_child IS NULL))")

        remaining_count = con.execute(
            f"SELECT COUNT(*) FROM {source} WHERE {remaining_where}", params
        ).fetchone()[0]

        # Group by clock pair + startpoint prefix (first path component) for bucket creation
        ext_groups = con.execute(f"""
            SELECT
                launch_clock, capture_clock,
                int_ext, int_ext_child,
                COALESCE(
                    driver_partition,
                    CASE WHEN POSITION('/' IN startpoint) > 0
                         THEN SUBSTRING(startpoint, 1, POSITION('/' IN startpoint) - 1)
                         ELSE startpoint
                    END
                ) as sp_prefix,
                COALESCE(
                    receiver_partition,
                    CASE WHEN POSITION('/' IN endpoint) > 0
                         THEN SUBSTRING(endpoint, 1, POSITION('/' IN endpoint) - 1)
                         ELSE endpoint
                    END
                ) as ep_prefix,
                COUNT(*) as path_count,
                ROUND(MIN(slack), 1) as worst_slack,
                ROUND(AVG(slack), 1) as avg_slack,
                ROUND(MIN(clock_percentage), 1) as worst_clock_pct,
                ROUND(AVG(clock_percentage), 1) as avg_clock_pct,
                ROUND(AVG(levels_of_logic), 0) as avg_lol
            FROM {source}
            WHERE {remaining_where}
            GROUP BY launch_clock, capture_clock, int_ext, int_ext_child, sp_prefix, ep_prefix
            ORDER BY path_count DESC
        """, params)

        ext_buckets = []
        ext_bucketed = 0
        bucket_idx = pteco_idx  # Continue priority numbering after PTECO
        for row in ext_groups.fetchall():
            lclk, cclk, ie, iec, sp, ep, cnt, worst_s, avg_s, worst_pct, avg_pct, avg_lol = row
            ext_bucketed += cnt
            bucket_idx += 1
            filters = []
            if lclk:
                filters.append(f"LaunchClk:{lclk}")
            if cclk:
                filters.append(f"CaptureClk:{cclk}")
            if sp:
                filters.append(f"StartPin:^{sp}.*")
            if ep:
                filters.append(f"EndPin:^{ep}.*")

            # Pre-classify; LLM will refine
            classif = _classify_bucket(worst_pct, avg_pct, avg_lol, worst_s, lclk, cclk)

            int_ext_label = f"{ie}/{iec}" if iec else (ie or "EXT")
            pct_str = f"{worst_pct}%w" if worst_pct is not None else "N/A"
            avg_pct_str = f"{avg_pct}%w" if avg_pct is not None else "N/A"
            desc = (f"[{int_ext_label}] {lclk}->{cclk} {sp}->{ep} "
                    f"({cnt} paths, worst {worst_s}ps/{pct_str}, avg {avg_s}ps/{avg_pct_str}, "
                    f"avg_lol={avg_lol})")

            ext_buckets.append({
                "priority": bucket_idx,
                "filters": filters,
                "classification": classif,
                "description": desc,
                "auto": True,
                "path_count": cnt,
                "worst_slack": worst_s,
                "avg_clock_pct": avg_pct,
                "worst_clock_pct": worst_pct,
            })

        # ── Catch-all for any stragglers (should be ~0 if grouping is exhaustive) ──
        catchall_count = remaining_count - ext_bucketed
        if catchall_count > 0:
            ext_buckets.append({
                "priority": 99,
                "filters": [],  # empty = matches everything not matched above
                "classification": "CLASSIF_FCT",
                "description": f"Catch-all: {catchall_count} remaining paths not covered by specific groups",
                "auto": True,
                "path_count": catchall_count,
            })

        # Build compact summary for LLM classification (PO_INT + C2C/EXT need IRIS labels)
        llm_summary = []
        for i, b in enumerate(po_int_buckets):
            llm_summary.append({
                "idx": i,
                "type": "PO_INT",
                "path_count": b["path_count"],
                "classification": b["classification"],
                "description": b["description"],
                "worst_clock_pct": b.get("worst_clock_pct"),
                "avg_clock_pct": b.get("avg_clock_pct"),
                "worst_slack": b.get("worst_slack"),
            })
        offset = len(po_int_buckets)
        for i, b in enumerate(ext_buckets):
            llm_summary.append({
                "idx": offset + i,
                "type": "C2C_EXT",
                "path_count": b["path_count"],
                "classification": b["classification"],
                "description": b["description"],
                "worst_clock_pct": b.get("worst_clock_pct"),
                "avg_clock_pct": b.get("avg_clock_pct"),
                "worst_slack": b.get("worst_slack"),
            })

        return {
            "block": block or os.path.basename(csv_path).split('.')[0],
            "run_label": run_label or csv_path,
            "mode": mode,
            "total_failing": total_failing,
            "summary": {"columns": sum_cols, "rows": sum_rows},
            "auto_buckets": {
                "po_int": {"bucket_count": len(po_int_buckets), "total_paths": po_int_total},
                "pteco": {"bucket_count": len(pteco_buckets), "total_paths": pteco_total},
                "c2c_ext": {"bucket_count": len(ext_buckets), "total_paths": remaining_count},
            },
            "buckets_for_classification": llm_summary,
            "_po_int_buckets": po_int_buckets,
            "_pteco_buckets": pteco_buckets,
            "_ext_buckets": ext_buckets,
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


# Column name mapping: timinglite filter name → DuckDB column name
FILTER_COL_MAP = {
    "LaunchClk": "launch_clock",
    "CaptureClk": "capture_clock",
    "StartPin": "startpoint",
    "EndPin": "endpoint",
    "PercentPeriod": "clock_percentage",
    "PathType": "path_type",
    "PathGroup": "path_group",
}


def _csv_source_with_aliases(con, csv_path):
    """Build a SQL source expression that aliases CSV columns to standard names.

    Raw CSVs can have different column names (e.g. start_clock vs launch_clock).
    Returns a subquery that normalizes to our standard schema.
    """
    raw_src = f"read_csv_auto('{csv_path}')"
    col_check = con.execute(f"SELECT * FROM {raw_src} LIMIT 0")
    csv_cols = {d[0].lower() for d in col_check.description}
    csv_types = {d[0].lower(): str(d[1]) for d in col_check.description}

    def col_or_null(standard, *alternatives, cast_to=None):
        for alt in (standard,) + alternatives:
            if alt in csv_cols:
                expr = f'"{alt}"'
                if cast_to and 'VARCHAR' in csv_types.get(alt, '').upper():
                    expr = f'TRY_CAST("{alt}" AS {cast_to})'
                return f'{expr} AS {standard}'
        return f"NULL AS {standard}"

    aliases = [
        col_or_null("slack", "normal_slack", cast_to="DOUBLE"),
        col_or_null("clock_percentage", "percent_period", cast_to="DOUBLE"),
        col_or_null("period", "start_clock_period", cast_to="DOUBLE"),
        col_or_null("startpoint", "start_pin"),
        col_or_null("endpoint", "end_pin"),
        col_or_null("launch_clock", "start_clock"),
        col_or_null("capture_clock", "end_clock"),
        col_or_null("path_group"),
        col_or_null("int_ext"),
        col_or_null("int_ext_child"),
        col_or_null("child_int_type"),
        col_or_null("driver_partition"),
        col_or_null("receiver_partition"),
        col_or_null("levels_of_logic", "number_data_cells", cast_to="INTEGER"),
        col_or_null("path_type", "path_delay_type"),
    ]

    # If clock_percentage is NULL but we have slack and period, derive it
    has_clock_pct = any(alt in csv_cols for alt in ("clock_percentage", "percent_period"))
    has_period = any(alt in csv_cols for alt in ("period", "start_clock_period"))
    has_slack = any(alt in csv_cols for alt in ("slack", "normal_slack"))
    if not has_clock_pct and has_period and has_slack:
        # Replace the NULL clock_percentage alias with a derived formula
        aliases = [a if not a.endswith("AS clock_percentage") else
                   "CASE WHEN period > 0 THEN ROUND(100.0 * ABS(slack) / period, 1) ELSE NULL END AS clock_percentage"
                   for a in aliases]

    return f"(SELECT {', '.join(aliases)} FROM {raw_src}) AS csv_data"


def validate_buckets(con, buckets, block, run_label, mode, csv_path=None):
    """Test bucket filter coverage against actual failing paths.

    For each bucket, builds a SQL WHERE clause from its regex filters and counts
    how many failing paths it matches. Returns per-bucket match counts and the
    total unmatched (catch-all) count with sample unmatched paths.
    """
    try:
        if csv_path:
            source = _csv_source_with_aliases(con, csv_path)
            base_where = "slack < 0"
            params = []
        else:
            source = "paths"
            base_where = "block = ? AND run_label = ? AND mode = ? AND slack < 0"
            params = [block, run_label, mode]

        path_type = "max" if mode == "setup" else "min"

        # Get total failing
        total_row = con.execute(
            f"SELECT COUNT(*) FROM {source} WHERE {base_where}", params
        ).fetchone()
        total_failing = total_row[0]

        bucket_results = []
        all_matched_conditions = []

        for i, bucket in enumerate(buckets):
            raw_filters = bucket.get("filters", [])
            # Remove PathType from filters (we add it)
            raw_filters = [f for f in raw_filters if not f.startswith("PathType:")]
            filters = [f"PathType:{path_type}"] + [_sanitize_filter_regex(f) for f in raw_filters]

            conditions = []
            for filt in filters:
                if ':' not in filt:
                    continue
                col_name, regex_val = filt.split(':', 1)
                db_col = FILTER_COL_MAP.get(col_name, col_name)
                if db_col == "path_type":
                    conditions.append(f"path_type = '{path_type}'")
                elif db_col == "clock_percentage":
                    # PercentPeriod filters are numeric comparisons, not regex
                    # Skip for now — they don't significantly affect coverage
                    continue
                else:
                    # Use regexp_matches for regex filters
                    safe_regex = regex_val.replace("'", "''")
                    conditions.append(f"regexp_matches({db_col}, '{safe_regex}')")

            if not conditions:
                bucket_results.append({
                    "bucket_index": i,
                    "classification": bucket.get("classification", ""),
                    "description": bucket.get("description", "")[:80],
                    "matched_paths": 0,
                    "error": "no valid filters",
                })
                continue

            bucket_where = " AND ".join(conditions)
            full_where = f"{base_where} AND {bucket_where}"

            try:
                count_row = con.execute(
                    f"SELECT COUNT(*) FROM {source} WHERE {full_where}", params
                ).fetchone()
                matched = count_row[0]
            except Exception as e:
                bucket_results.append({
                    "bucket_index": i,
                    "classification": bucket.get("classification", ""),
                    "description": bucket.get("description", "")[:80],
                    "matched_paths": 0,
                    "error": f"regex error: {str(e)[:100]}",
                })
                continue

            bucket_results.append({
                "bucket_index": i,
                "classification": bucket.get("classification", ""),
                "description": bucket.get("description", "")[:80],
                "matched_paths": matched,
                "pct_of_total": round(100 * matched / total_failing, 1) if total_failing else 0,
            })
            all_matched_conditions.append(f"({bucket_where})")

        # Count unmatched (catch-all) paths
        if all_matched_conditions:
            any_matched = " OR ".join(all_matched_conditions)
            unmatched_where = f"{base_where} AND NOT ({any_matched})"
        else:
            unmatched_where = base_where

        unmatched_count = con.execute(
            f"SELECT COUNT(*) FROM {source} WHERE {unmatched_where}", params
        ).fetchone()[0]

        # Sample unmatched paths for debugging
        unmatched_sample = con.execute(f"""
            SELECT startpoint, endpoint, launch_clock, capture_clock,
                   driver_partition, receiver_partition, int_ext, slack,
                   clock_percentage, levels_of_logic
            FROM {source}
            WHERE {unmatched_where}
            ORDER BY slack ASC
            LIMIT 30
        """, params)
        sample_cols = [d[0] for d in unmatched_sample.description]
        sample_rows = [list(r) for r in unmatched_sample.fetchall()]

        # Compact bucket coverage: only show broken buckets (0 matches) and a summary line for others
        broken_buckets = [b for b in bucket_results if b.get("matched_paths", 0) == 0]
        working_buckets = [b for b in bucket_results if b.get("matched_paths", 0) > 0]
        coverage_summary = [
            {"bucket_index": b["bucket_index"], "classification": b["classification"],
             "matched": b["matched_paths"], "pct": b.get("pct_of_total", 0)}
            for b in working_buckets
        ]

        return {
            "total_failing": total_failing,
            "total_matched_by_buckets": total_failing - unmatched_count,
            "total_unmatched": unmatched_count,
            "unmatched_pct": round(100 * unmatched_count / total_failing, 1) if total_failing else 0,
            "target_pct": 5.0,
            "meets_target": (100 * unmatched_count / total_failing) < 5.0 if total_failing else True,
            "working_buckets": coverage_summary,
            "broken_buckets": broken_buckets,
            "unmatched_sample": {"columns": sample_cols, "rows": sample_rows},
            "hint": "Use the unmatched_sample to create additional buckets and re-validate." if unmatched_count > 0 else "All paths covered!",
        }
    except Exception as e:
        return {"error": str(e)}


# Auto-buckets (PO_INT + PTECO + C2C/EXT) created by Python during triage — exported directly
_auto_buckets_for_export = []
_last_exported_bucket_path = None


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
        global _last_exported_bucket_path
        block = tool_input["block"]
        run_label = tool_input["run_label"]
        mode = tool_input["mode"]
        output_path = tool_input["output_path"]
        llm_buckets = tool_input.get("buckets", [])
        # All buckets are auto-generated by Python. LLM may pass empty list or classified versions.
        # If LLM passed classified C2C/EXT buckets, merge their classifications into auto-buckets.
        if llm_buckets:
            # Build a map of LLM classifications by filter signature for matching
            llm_classif = {}
            for b in llm_buckets:
                classif = b.get("classification", "")
                if classif in ("CLASSIF_PO_INT", "CLASSIF_PTECO"):
                    continue  # Skip — Python handles these
                key = tuple(sorted(b.get("filters", [])))
                if key:
                    llm_classif[key] = {
                        "classification": classif,
                        "description": b.get("description", ""),
                    }
            # Apply LLM classifications to matching auto-buckets
            updated = 0
            for ab in _auto_buckets_for_export:
                if not ab.get("auto"):
                    continue
                key = tuple(sorted(ab.get("filters", [])))
                if key in llm_classif:
                    ab["classification"] = llm_classif[key]["classification"]
                    if llm_classif[key]["description"]:
                        ab["description"] = llm_classif[key]["description"]
                    updated += 1
            if updated:
                console.print(f"  [dim]Applied LLM classifications to {updated} C2C/EXT buckets[/dim]")
        # Export ALL auto-buckets
        all_buckets = list(_auto_buckets_for_export)
        console.print(f"\n[dim]Generating bucket file: {output_path}[/dim]")
        console.print(f"  [dim]{len(all_buckets)} total auto-buckets[/dim]\n")
        result = export_bucket_file(all_buckets, output_path, block, run_label, mode)
        _last_exported_bucket_path = result.get("path")
        console.print(f"  [bold green]Wrote {result['bucket_count']} buckets[/bold green] to {result['path']}")
        console.print(f"  [dim]Load in Timing Lite: timinglite.py --bucket {result['path']} <report>[/dim]\n")
        return json.dumps(result, default=str)

    elif tool_name == "validate_buckets":
        mode = tool_input["mode"]
        buckets = tool_input["buckets"]
        block = tool_input.get("block")
        run_label = tool_input.get("run_label")
        csv_path = tool_input.get("csv_path")
        console.print(f"\n[dim]Validating {len(buckets)} buckets against failing paths...[/dim]\n")
        result = validate_buckets(con, buckets, block, run_label, mode, csv_path=csv_path)
        if "error" not in result:
            matched = result["total_matched_by_buckets"]
            total = result["total_failing"]
            unmatched = result["total_unmatched"]
            pct = result["unmatched_pct"]
            status = "[bold green]PASS[/bold green]" if result["meets_target"] else "[bold red]FAIL[/bold red]"
            console.print(f"  Coverage: {matched}/{total} paths matched ({100-pct:.1f}%)")
            console.print(f"  Catch-all: {unmatched} paths ({pct}%) — target <5% — {status}")
        else:
            console.print(f"[red]{result['error']}[/red]")
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
        with client.messages.stream(
            model=model,
            max_tokens=max_tokens,
            system=system_prompt,
            tools=TOOL_SCHEMA,
            messages=messages,
        ) as stream:
            response = stream.get_final_message()

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
    parser.add_argument("--persona", choices=["sto", "po"], default="sto",
                        help="Triage persona: 'sto' (Section Timing Owner, focuses on C2C/EXT, default) or 'po' (Partition Owner, focuses on partition internals)")
    parser.add_argument("--partition", "-p", help="Partition name for PO mode (e.g., pard2d1uladda1). Required when --persona po")
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

            block_label = args.block or os.path.basename(csv_path or 'unknown').split('.')[0]
            run_label = args.run or csv_path or 'ad-hoc'
            persona = args.persona or 'sto'
            partition = args.partition
            output_path = args.output or f"./buckets/{block_label}_{args.mode}.bucket"

            if persona == 'po':
                if not partition:
                    console.print("[red]--persona po requires --partition <partition_name>[/red]")
                    sys.exit(1)
                output_path = args.output or f"./buckets/{partition}_{args.mode}.bucket"

            # Pre-call triage_timing_run in Python (avoids LLM path typos & saves a tool round-trip)
            global _last_exported_bucket_path
            console.print(f"\n[dim]Running triage analysis...[/dim]")
            triage_data = triage_timing_run(con, block_label, run_label, args.mode, csv_path=csv_path)
            if "error" in triage_data:
                console.print(f"[red]Triage failed: {triage_data['error']}[/red]")
                sys.exit(1)

            summary = triage_data["summary"]["rows"][0] if triage_data["summary"]["rows"] else []
            total_failing = triage_data.get("total_failing", summary[0] if summary else 0)
            if summary:
                console.print(f"  [bold]{summary[0]}[/bold] failing paths, worst slack: [red]{summary[1]}ps[/red]")
            auto = triage_data.get("auto_buckets", {})
            po_int_count = auto.get("po_int", {}).get("total_paths", 0)
            pteco_count = auto.get("pteco", {}).get("total_paths", 0)
            ext_count = auto.get("c2c_ext", {}).get("total_paths", 0)
            po_int_buckets = triage_data.get("_po_int_buckets", [])
            pteco_buckets = triage_data.get("_pteco_buckets", [])
            ext_buckets = triage_data.get("_ext_buckets", [])
            buckets_for_classif = triage_data.get("buckets_for_classification", [])
            n_auto = len(po_int_buckets) + len(pteco_buckets) + len(ext_buckets)
            console.print(f"  Auto-bucketed: {po_int_count} PO_INT ({len(po_int_buckets)} buckets) + "
                          f"{pteco_count} PTECO ({len(pteco_buckets)} buckets) + "
                          f"{ext_count} C2C/EXT ({len(ext_buckets)} buckets)")
            console.print(f"  Total: {n_auto} auto-buckets covering all {total_failing} paths")
            console.print(f"  LLM will classify {len(buckets_for_classif)} buckets with IRIS rules\n")

            # Store ALL auto-buckets for export — PO_INT + PTECO are final, ext_buckets may get LLM classification updates
            _auto_buckets_for_export.clear()
            _auto_buckets_for_export.extend(po_int_buckets)
            _auto_buckets_for_export.extend(pteco_buckets)
            _auto_buckets_for_export.extend(ext_buckets)

            # Compact data for LLM: bucket summaries to classify
            llm_data = {
                "block": triage_data.get("block"),
                "mode": triage_data.get("mode"),
                "summary": triage_data.get("summary"),
                "auto_bucket_counts": {
                    "po_int": f"{po_int_count} paths in {len(po_int_buckets)} buckets",
                    "pteco": f"{pteco_count} paths in {len(pteco_buckets)} buckets",
                    "c2c_ext": f"{ext_count} paths in {len(ext_buckets)} buckets",
                },
                "buckets_for_classification": buckets_for_classif,
            }
            triage_json = json.dumps(llm_data, default=str)

            export_params = f"block='{block_label}', run_label='{run_label}', mode='{args.mode}', output_path='{output_path}'"

            if persona == 'po':
                triage_question = (
                    f"Triage all failing {args.mode} paths in partition '{partition}' "
                    f"(block '{block_label}', run '{run_label}').\n\n"
                    f"You are triaging as a PARTITION OWNER (PO) for partition '{partition}'.\n\n"
                    f"Here is the triage data (already computed — do NOT call triage_timing_run):\n"
                    f"{triage_json}\n\n"
                    f"ALL {total_failing} paths are auto-bucketed by Python ({n_auto} buckets).\n"
                    f"Your ONLY job: review the {len(buckets_for_classif)} buckets in buckets_for_classification, "
                    f"refine their IRIS classifications, then call export.\n\n"
                    f"Workflow:\n"
                    f"1. Review each item in buckets_for_classification.\n"
                    f"   Each has a pre-assigned classification — refine using IRIS rules:\n"
                    f"   - worst_clock_pct > 100% → CLASSIF_CONSTRAINTS\n"
                    f"   - avg_clock_pct 2-30% → CLASSIF_PO_OPT\n"
                    f"   - High avg levels_of_logic → HRP-001 → CLASSIF_FCT\n"
                    f"   - Otherwise → CLASSIF_FCT with specific IRIS rule\n"
                    f"2. ALWAYS call export_bucket_file({export_params}, buckets=[]).\n"
                    f"   Python will export ALL auto-buckets. You MUST call this.\n"
                    f"3. Print triage summary: for each bucket group, print classification + stats."
                )
            else:
                triage_question = (
                    f"Triage all failing {args.mode} paths in block '{block_label}', run '{run_label}'.\n\n"
                    f"You are triaging as a SECTION TIMING OWNER (STO).\n\n"
                    f"Here is the triage data (already computed — do NOT call triage_timing_run):\n"
                    f"{triage_json}\n\n"
                    f"ALL {total_failing} paths are auto-bucketed by Python ({n_auto} buckets).\n"
                    f"Your ONLY job: review the {len(buckets_for_classif)} buckets in buckets_for_classification, "
                    f"refine their IRIS classifications, then call export.\n\n"
                    f"Workflow:\n"
                    f"1. Review each item in buckets_for_classification.\n"
                    f"   Each has a pre-assigned classification — refine using the IRIS waterfall:\n"
                    f"   Stage 1 - Constraints Check → CLASSIF_CONSTRAINTS (IOC, CON rules)\n"
                    f"   Stage 2 - Feedthrough Check → CLASSIF_FCT (FTC rules)\n"
                    f"   Stage 3 - Optimization Check → CLASSIF_PO_OPT (2-30% window, by partition)\n"
                    f"   Stage 4 - Additional Check → CLASSIF_FCT (HRP, MOP, SKW rules)\n"
                    f"2. ALWAYS call export_bucket_file({export_params}, buckets=[]).\n"
                    f"   Python exports ALL {n_auto} auto-buckets. You MUST call this.\n"
                    f"3. Print triage summary: bucket classifications grouped by partition, then totals."
                )
            run_agent(con, client, triage_question, args.block, args.run, args.mode,
                      model=model, reports_dir=args.reports_dir, max_tokens=32768)
            # Post-triage check: did the bucket file get created?
            actual_path = _last_exported_bucket_path or output_path
            if os.path.isfile(actual_path):
                console.print(f"\n[bold green]\u2713 Bucket file written:[/bold green] {os.path.abspath(actual_path)}")
                console.print(f"[dim]  Load in Timing Lite: timinglite.py --bucket {os.path.abspath(actual_path)} <report>[/dim]")
            elif actual_path != output_path and os.path.isfile(output_path):
                console.print(f"\n[bold green]\u2713 Bucket file written:[/bold green] {os.path.abspath(output_path)}")
                console.print(f"[dim]  Load in Timing Lite: timinglite.py --bucket {os.path.abspath(output_path)} <report>[/dim]")
            elif _auto_buckets_for_export:
                # Fallback: LLM didn't call export (token exhaustion?) — export with default classifications
                console.print(f"\n[bold yellow]LLM did not call export — exporting {len(_auto_buckets_for_export)} auto-buckets with default classifications...[/bold yellow]")
                os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
                result = export_bucket_file(list(_auto_buckets_for_export), output_path, block_label, run_label, args.mode)
                _last_exported_bucket_path = result.get("path")
                console.print(f"  [bold green]Wrote {result['bucket_count']} buckets[/bold green] to {result['path']}")
                console.print(f"  [dim]Load in Timing Lite: timinglite.py --bucket {result['path']} <report>[/dim]")
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
