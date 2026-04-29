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

LEGACY_BUCKET_CLASSIFICATIONS = {
    "CLASSIF_CONSTRAINTS": "CLASSIF_CONS",
    "CLASSIF_CONS": "CLASSIF_CONS",
    "CLASSIF_PTECO": "CLASSIF_OPT",
    "CLASSIF_PO_OPT": "CLASSIF_OPT",
    "CLASSIF_OPT": "CLASSIF_OPT",
    "CLASSIF_FCT": "CLASSIF_FCT",
    "CLASSIF_WAIVE0P5": "CLASSIF_WAIVE0P5",
    "CLASSIF_WAIVE0P8": "CLASSIF_WAIVE0P8",
    "CLASSIF_PO_INT": "CLASSIF_PARs_INT",
    "CLASSIF_PARS_INT": "CLASSIF_PARs_INT",
    "CLASSIF_PARs_INT": "CLASSIF_PARs_INT",
    "Partition_Internals": "CLASSIF_PARs_INT",
}

WAIVER_MILESTONE_RULES = {
    "0p5": {
        "setup": {
            "filter": "PercentPeriod:>-20",
            "sql": "clock_percentage > -20",
            "label": "0p5 milestone waiver",
        },
        "hold": {
            "filter": "Slack:>-100",
            "sql": "slack > -100",
            "label": "0p5 milestone waiver",
        },
    },
    "0p8": {
        "setup": {
            "filter": "PercentPeriod:>-5",
            "sql": "clock_percentage > -5",
            "label": "0p8 milestone waiver",
        },
        "hold": {
            "filter": "Slack:>-30",
            "sql": "slack > -30",
            "label": "0p8 milestone waiver",
        },
    },
    "1p0": None,
}

TOOL_SCHEMA = [
    {
        "name": "query_timing_db",
        "description": "Execute a SQL query against the timing DuckDB database or any temporary DuckDB view created during triage. Returns results as a list of rows. Use this for blocks/runs in the database and for triage workspaces such as triage_remaining_paths.",
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
        "description": "Execute a SQL query against a CSV.gz file directly from NFS using DuckDB's read_csv_auto. No ingest needed. Use for ad-hoc analysis of any timing CSV on disk. Raw PSGen CSVs usually expose headers like start_pin/end_pin/start_clock/end_clock/path_delay_type rather than normalized names like startpoint/endpoint/launch_clock/capture_clock/path_type, so alias columns in SQL when needed. Example: SELECT slack, clock_percentage, start_pin AS startpoint, end_pin AS endpoint FROM read_csv_auto('/path/to/report_summary.max.csv.gz') WHERE slack < 0 ORDER BY slack LIMIT 20",
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
        "description": "Analyze all failing paths and return a two-pass triage workspace. Pass 1 is Python auto-bucketing for the obvious categories. Pass 2 is LLM bucketing over the actual residual paths that do not match those auto-buckets. Returns: (1) auto_buckets — Python-generated buckets to include as-is; (2) remaining_c2c_ext — summary plus a temp-view name that the LLM should query directly for raw residual paths.",
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
                },
                "milestone": {
                    "type": "string",
                    "enum": ["0p5", "0p8", "1p0"],
                    "description": "Optional milestone waiver profile. 0p5 and 0p8 add waiver auto-buckets; 1p0 has no waiver bucket."
                }
            },
            "required": ["mode"]
        }
    },
    {
        "name": "export_bucket_file",
        "description": "Generate a timinglite-compatible bucket file from triage results. Each bucket has filter expressions (timinglite syntax), a classification (CLASSIF_CONS/CLASSIF_OPT/CLASSIF_FCT/CLASSIF_WAIVE0P5/CLASSIF_WAIVE0P8), and an optional tag kept for internal categorization. The emitted bucket line writes the classification immediately after the filter string so the file matches known-good Timing Lite syntax.",
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
                                "description": "Bucket priority (1 = default, higher = checked first)"
                            },
                            "filters": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Filter expressions in timinglite syntax: LaunchClk:<regex>, CaptureClk:<regex>, StartPin:<regex>, EndPin:<regex>, PercentPeriod:<comparison>"
                            },
                            "classification": {
                                "type": "string",
                                "enum": ["CLASSIF_CONS", "CLASSIF_OPT", "CLASSIF_FCT", "CLASSIF_PARs_INT", "CLASSIF_WAIVE0P5", "CLASSIF_WAIVE0P8"],
                                "description": "CLASSIF_CONS (constraints), CLASSIF_OPT (PTECO/optimization), CLASSIF_FCT (floorplan/manual fix), CLASSIF_PARs_INT (partition internals, PO-owned, untriaged), CLASSIF_WAIVE0P5/CLASSIF_WAIVE0P8 (milestone waiver buckets)"
                            },
                            "tag": {
                                "type": "string",
                                "enum": ["TAG_PO", "TAG_PTECO", "TAG_FCT", "TAG_CONS", "TAG_IO_CONS", "TAG_HIP", "TAG_UNTRIAGED", "TAG_FCL"],
                                "description": "Optional internal category tag. Not emitted into the bucket line."
                            },
                            "description": {
                                "type": "string",
                                "description": "Root cause analysis and recommended fix — written as # comment in bucket file so timinglite users understand why this bucket is failing"
                            }
                        },
                        "required": ["filters", "classification"]
                    }
                }
            },
            "required": ["block", "run_label", "mode", "output_path", "buckets"]
        }
    },
    {
        "name": "validate_buckets",
        "description": "Test bucket filter coverage against actual failing paths. During triage, Python auto-buckets are merged automatically with the LLM buckets you provide, so coverage reflects the full final bucket set. Returns per-bucket match counts, total unmatched path count and percentage, a sample of unmatched paths, and a temp view name for querying the still-unmatched residual paths. Use this after creating candidate buckets, inspect the unmatched residual, refine, and repeat before export.",
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
    {
        "name": "review_auto_buckets",
        "description": "Inspect the Python-generated auto-buckets before export so you can add a concise LLM hypothesis for each bucket. Returns, for each selected auto-bucket, its current description, filters, summary stats, top path-group mix, top clock-pair mix, and a few worst example paths. Use this to understand what a stable Python bucket appears to contain before calling annotate_auto_buckets.",
        "input_schema": {
            "type": "object",
            "properties": {
                "mode": {
                    "type": "string",
                    "enum": ["setup", "hold"],
                    "description": "setup or hold"
                },
                "block": {
                    "type": "string",
                    "description": "Block name"
                },
                "run_label": {
                    "type": "string",
                    "description": "Run label"
                },
                "csv_path": {
                    "type": "string",
                    "description": "Path to CSV.gz for ad-hoc mode"
                },
                "bucket_indexes": {
                    "type": "array",
                    "items": {"type": "integer"},
                    "description": "Optional subset of auto-bucket indexes to inspect. Omit to inspect all auto-buckets."
                },
                "max_samples": {
                    "type": "integer",
                    "description": "How many worst paths to return per bucket (default 3)."
                }
            },
            "required": ["mode"]
        }
    },
    {
        "name": "annotate_auto_buckets",
        "description": "Append or replace an LLM-generated explanation for one or more Python auto-buckets while preserving the original Python description. Use after review_auto_buckets. The added text is emitted in the final bucket file as 'LLM description: ...'.",
        "input_schema": {
            "type": "object",
            "properties": {
                "annotations": {
                    "type": "array",
                    "description": "LLM descriptions to attach to existing auto-buckets by index.",
                    "items": {
                        "type": "object",
                        "properties": {
                            "bucket_index": {
                                "type": "integer",
                                "description": "Index of the auto-bucket within the current Python auto-bucket list"
                            },
                            "llm_description": {
                                "type": "string",
                                "description": "Short hypothesis for what the bucket likely represents or why it is failing"
                            }
                        },
                        "required": ["bucket_index", "llm_description"]
                    }
                }
            },
            "required": ["annotations"]
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


def _normalize_bucket_classification(classification):
    """Map older bucket class names to the current export schema."""
    normalized = (classification or "").strip()
    return LEGACY_BUCKET_CLASSIFICATIONS.get(normalized, normalized)


def load_existing_bucket_file(bucket_path):
    """Parse active timinglite bucket lines into validate/export bucket dicts."""
    if not os.path.isfile(bucket_path):
        raise FileNotFoundError(f"Bucket file not found: {bucket_path}")

    buckets = []
    skipped_lines = []
    with open(bucket_path, "r", encoding="utf-8") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            line = raw_line.strip()
            if not line:
                continue
            if line.startswith("#INCLUDE"):
                skipped_lines.append({"line": line_number, "reason": "include_not_loaded"})
                continue
            if line.startswith("#"):
                continue

            match = re.match(r"^(?P<priority>\d+)\s+(?P<filters>\S+)\s+(?P<rest>.+)$", line)
            if not match:
                skipped_lines.append({"line": line_number, "reason": "unparsed"})
                continue

            rest_tokens = match.group("rest").split()
            class_index = next(
                (
                    index for index, token in enumerate(rest_tokens)
                    if re.fullmatch(r"CLASSIF_[A-Za-z0-9_]+", token) or token == "Partition_Internals"
                ),
                None,
            )
            if class_index is None:
                skipped_lines.append({"line": line_number, "reason": "missing_classification"})
                continue

            classification = rest_tokens[class_index]
            description_tokens = [
                token for index, token in enumerate(rest_tokens)
                if index != class_index and not token.startswith(("OWNER_", "TRIAGER_", "TAG_"))
            ]

            buckets.append({
                "priority": int(match.group("priority")),
                "filters": [f for f in match.group("filters").split("&&") if f],
                "classification": _normalize_bucket_classification(classification),
                "description": " ".join(description_tokens),
            })

    if not buckets:
        raise ValueError(f"No active bucket definitions found in {bucket_path}")

    return {
        "path": os.path.abspath(bucket_path),
        "bucket_count": len(buckets),
        "skipped_line_count": len(skipped_lines),
        "skipped_lines": skipped_lines[:10],
        "buckets": buckets,
    }


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

def resolve_triage_csv_path(reports_dir, mode, persona="sto", partition=None):
    """Resolve the CSV to use for ad-hoc triage from a reports directory or direct file path.

    In PO mode, require a partition-specific report such as
    <partition>.*.report_summary.max.csv.gz when resolving from a reports directory.
    """
    suffix_base = f"report_summary.{'max' if mode == 'setup' else 'min'}.csv"
    suffixes = [f"{suffix_base}.gz", suffix_base]

    if os.path.isfile(reports_dir):
        return {
            "csv_path": reports_dir,
            "selection_reason": "direct file path",
        }

    if not os.path.isdir(reports_dir):
        return {
            "error": f"Directory not found: {reports_dir}",
        }

    candidates = sorted(
        f for f in os.listdir(reports_dir)
        if any(f.endswith(suffix) for suffix in suffixes)
    )
    if not candidates:
        return {
            "error": f"No *{suffixes[0]} or *{suffixes[1]} found in {reports_dir}",
        }

    if persona == "po" and partition:
        partition_prefixes = [f"{partition}.", f"{partition}_"]
        preferred = [
            f for f in candidates
            if any(f.startswith(prefix) for prefix in partition_prefixes)
        ]
        if preferred:
            return {
                "csv_path": os.path.join(reports_dir, preferred[0]),
                "selection_reason": f"partition-specific report for {partition}",
            }
        return {
            "error": (
                f"Partition report not found for '{partition}' in {reports_dir}. "
                f"Expected a file matching {partition}.*.{suffix_base}[.gz]"
            ),
        }

    return {
        "csv_path": os.path.join(reports_dir, candidates[0]),
        "selection_reason": "first matching report_summary CSV",
    }

def _partition_expr_sql(pin_col, leaf_depth=1, top_level_leaf_parts=None, partition_col=None):
    """Return SQL expression for the real partition name for a hierarchical pin."""
    top_level_leaf_parts = set(top_level_leaf_parts or [])
    top_part = f"split_part({pin_col}, '/', 1)"
    if leaf_depth > 1:
        if top_level_leaf_parts:
            top_list = ", ".join(f"'{part}'" for part in sorted(top_level_leaf_parts))
            base_expr = (
                f"CASE "
                f"WHEN {pin_col} NOT LIKE '%/%' THEN {top_part} "
                f"WHEN {top_part} IN ({top_list}) THEN {top_part} "
                f"ELSE split_part({pin_col}, '/', {leaf_depth}) END"
            )
        else:
            base_expr = (
                f"CASE "
                f"WHEN {pin_col} NOT LIKE '%/%' THEN {top_part} "
                f"ELSE split_part({pin_col}, '/', {leaf_depth}) END"
            )
    else:
        base_expr = top_part

    if partition_col:
        return f"COALESCE({partition_col}, {base_expr})"
    return base_expr


def _append_scope_filter(base_where, extra_scope):
    if not extra_scope:
        return base_where
    return f"({base_where}) AND ({extra_scope})"


def _current_po_scope_sql(block=None):
    """Return the active PO scope SQL for validate/review helper calls, if any."""
    scope = _active_triage_scope or {}
    if scope.get("persona") != "po":
        return None

    partition = scope.get("partition")
    if not partition:
        return None

    scoped_block = block or scope.get("block")
    leaf_depth = scope.get("leaf_depth", 1)
    top_level_leaf_parts = set(BLOCKS.get(scoped_block, {}).get("leaf_partitions_n1", [])) if scoped_block else set()
    sp_part = _partition_expr_sql("startpoint", leaf_depth, top_level_leaf_parts, "driver_partition")
    ep_part = _partition_expr_sql("endpoint", leaf_depth, top_level_leaf_parts, "receiver_partition")
    partition_sql = _sql_literal(partition)
    return (
        f"(({sp_part}) = {partition_sql}) "
        f"AND (({ep_part}) = {partition_sql}) "
        f"AND (child_int_type = 'INT_AllChildren' OR int_ext = 'INT')"
    )


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


def triage_timing_run(con, block, run_label, mode, csv_path=None, leaf_depth=1, milestone=None,
                      persona="sto", partition=None):
    """Analyze failing paths and group into triage bucket candidates.

    Works in two modes:
    - Ingested data: queries the paths table (block/run_label/mode)
    - Ad-hoc CSV: queries a CSV.gz file directly via read_csv_auto (csv_path)

    leaf_depth: hierarchy level that defines the leaf partition.
      1 (default) = n-1 level, uses PSGen's thru_children directly.
      2 = n-2 level, uses split_part(pin, '/', 2) to split INT_AllChildren
          into Partition_Internals vs INT_C2C.

    For large runs (100K+ paths), auto-buckets the obvious categories in Python
    and then materializes the true residual set of paths that do not match those
    auto-bucket filters. The LLM should inspect that residual set directly.
    """
    try:
        if csv_path:
            # Ad-hoc mode: normalize CSV column names to our standard schema
            source = _csv_source_with_aliases(con, csv_path)
            where = "slack < 0"
            where_sql = where
            params = []
        else:
            # Ingested mode: query paths table
            source = "paths"
            where = "block = ? AND run_label = ? AND mode = ? AND slack < 0"
            where_sql = (
                f"block = {_sql_literal(block)} AND run_label = {_sql_literal(run_label)} "
                f"AND mode = {_sql_literal(mode)} AND slack < 0"
            )
            params = [block, run_label, mode]

        top_level_leaf_parts = set(BLOCKS.get(block, {}).get("leaf_partitions_n1", [])) if block else set()

        def _partition_expr(pin_col, partition_col=None):
            """Return SQL expression for the real partition name for a pin path.

            Most memstack partitions live at n-2 (leaf_depth=2), but some partitions like
            pardfi are real partitions at n-1 and must not be split to a deeper child.
            """
            top_part = f"split_part({pin_col}, '/', 1)"
            if leaf_depth > 1:
                if top_level_leaf_parts:
                    top_list = ", ".join(f"'{part}'" for part in sorted(top_level_leaf_parts))
                    base_expr = (
                        f"CASE "
                        f"WHEN {pin_col} NOT LIKE '%/%' THEN {top_part} "
                        f"WHEN {top_part} IN ({top_list}) THEN {top_part} "
                        f"ELSE split_part({pin_col}, '/', {leaf_depth}) END"
                    )
                else:
                    base_expr = (
                        f"CASE "
                        f"WHEN {pin_col} NOT LIKE '%/%' THEN {top_part} "
                        f"ELSE split_part({pin_col}, '/', {leaf_depth}) END"
                    )
            else:
                base_expr = top_part

            if partition_col:
                return f"COALESCE({partition_col}, {base_expr})"
            return base_expr

        def _is_port_expr(pin_col, side):
            """Return SQL expression that identifies true block ports.

            Primary signal is path_group from the timing report:
            - INPUT_PATHS => startpoint is a block input port
            - OUTPUT_PATHS => endpoint is a block output port
            Also treat any slash-free name as a block port.
            """
            if side == "start":
                return f"(path_group = 'INPUT_PATHS' OR {pin_col} NOT LIKE '%/%')"
            return f"(path_group = 'OUTPUT_PATHS' OR {pin_col} NOT LIKE '%/%')"

        def _append_scope(base_where, extra_scope):
            if not extra_scope:
                return base_where
            return f"({base_where}) AND ({extra_scope})"

        scope_note = None
        if persona == "po":
            if not partition:
                return {"error": "PO triage requires a partition name"}
            sp_scope_part = _partition_expr("startpoint", "driver_partition")
            ep_scope_part = _partition_expr("endpoint", "receiver_partition")
            partition_sql = _sql_literal(partition)
            po_scope = (
                f"(({sp_scope_part}) = {partition_sql}) "
                f"AND (({ep_scope_part}) = {partition_sql}) "
                f"AND (child_int_type = 'INT_AllChildren' OR int_ext = 'INT')"
            )
            where = _append_scope(where, po_scope)
            where_sql = _append_scope(where_sql, po_scope)
            scope_note = (
                f"PO scope is limited to internal failing paths entirely within partition '{partition}'. "
                f"STO-owned C2C, EXT, input-port, and PTECO paths are excluded."
            )

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
        if persona == "po" and total_failing == 0:
            scope_target = csv_path or run_label
            return {
                "error": (
                    f"No failing internal paths found for partition '{partition}' in '{scope_target}'. "
                    f"Check that --partition matches the report content and that --reports-dir/--block point to the intended run."
                )
            }

        # ── Auto-bucket 1: INT paths → Partition_Internals or INT_C2C ──
        # Default (leaf_depth=1): PSGen's child_int_type + thru_children is sufficient.
        #   INT_AllChildren = all endpoints in same n-1 partition → Partition_Internals
        # Override (leaf_depth=2): INT_AllChildren needs splitting at n-2 level.
        #   Compare split_part(startpoint, '/', 2) vs split_part(endpoint, '/', 2)
        #   to separate same-partition (Partition_Internals) from cross-partition (INT_C2C).

        po_int_dict = {}      # Partition_Internals keyed by partition name (merge 1 + 1b)
        known_partition_names = set(top_level_leaf_parts)
        int_c2c_buckets = []  # INT_C2C (different leaf, STO owns)
        po_int_total = 0
        int_c2c_total = 0

        if persona != "po":
            if leaf_depth == 1:
                # Default: group by thru_children. All INT_AllChildren = Partition_Internals.
                # Partition internals: group by partition only (no clock split).
                # INT_C2C: not possible at leaf_depth=1 (all same partition).
                int_same_rows = con.execute(f"""
                    SELECT
                        thru_children as sp_part,
                        thru_children as ep_part,
                        NULL as launch_clock, NULL as capture_clock,
                        COUNT(*) as path_count,
                        ROUND(MIN(slack), 1) as worst_slack,
                        ROUND(AVG(slack), 1) as avg_slack,
                        ROUND(MIN(clock_percentage), 1) as worst_clock_pct,
                        ROUND(AVG(levels_of_logic), 0) as avg_lol
                    FROM {source}
                    WHERE {where}
                      AND child_int_type = 'INT_AllChildren'
                    GROUP BY thru_children
                    ORDER BY path_count DESC
                """, params).fetchall()
                int_c2c_rows = []
                # For remaining_where: exclude all INT_AllChildren
                int_exclude_cond = "child_int_type = 'INT_AllChildren'"
            else:
                # Override: split INT_AllChildren by n-2 component.
                # Same-leaf = Partition_Internals (group by partition only, no clock).
                # Different-leaf = INT_C2C (keep clock grouping).
                sp_leaf = _partition_expr("startpoint")
                ep_leaf = _partition_expr("endpoint")
                # First: same-leaf (Partition_Internals) — no clock grouping
                # IMPORTANT: fetchall() immediately — DuckDB's con.execute() returns the
                # connection itself, so a second execute() would overwrite the first result.
                int_same_rows = con.execute(f"""
                    SELECT
                        ({sp_leaf}) as sp_part,
                        ({ep_leaf}) as ep_part,
                        NULL as launch_clock, NULL as capture_clock,
                        COUNT(*) as path_count,
                        ROUND(MIN(slack), 1) as worst_slack,
                        ROUND(AVG(slack), 1) as avg_slack,
                        ROUND(MIN(clock_percentage), 1) as worst_clock_pct,
                        ROUND(AVG(levels_of_logic), 0) as avg_lol
                    FROM {source}
                    WHERE {where}
                      AND child_int_type = 'INT_AllChildren'
                      AND ({sp_leaf}) = ({ep_leaf})
                    GROUP BY sp_part, ep_part
                    ORDER BY path_count DESC
                """, params).fetchall()
                # Second: different-leaf (INT_C2C) — keep clock grouping
                int_c2c_rows = con.execute(f"""
                    SELECT
                        ({sp_leaf}) as sp_part,
                        ({ep_leaf}) as ep_part,
                        launch_clock, capture_clock,
                        COUNT(*) as path_count,
                        ROUND(MIN(slack), 1) as worst_slack,
                        ROUND(AVG(slack), 1) as avg_slack,
                        ROUND(MIN(clock_percentage), 1) as worst_clock_pct,
                        ROUND(AVG(levels_of_logic), 0) as avg_lol
                    FROM {source}
                    WHERE {where}
                      AND child_int_type = 'INT_AllChildren'
                      AND ({sp_leaf}) != ({ep_leaf})
                    GROUP BY sp_part, ep_part, launch_clock, capture_clock
                    ORDER BY path_count DESC
                """, params).fetchall()
                # For remaining_where: exclude ALL INT_AllChildren (both same-leaf and cross-leaf handled above)
                int_exclude_cond = "child_int_type = 'INT_AllChildren'"

            def _merge_po_int(part_name, count, worst_s, avg_s, worst_pct, avg_lol):
                """Merge partition internal stats into dict by partition name."""
                known_partition_names.add(part_name)
                if part_name in po_int_dict:
                    existing = po_int_dict[part_name]
                    total = existing["path_count"] + count
                    existing["path_count"] = total
                    existing["worst_s"] = min(existing["worst_s"], worst_s)
                    existing["avg_s"] = round((existing["avg_s"] * existing["_prev_count"] + avg_s * count) / total, 1)
                    existing["worst_pct"] = min(existing["worst_pct"], worst_pct) if worst_pct is not None else existing["worst_pct"]
                    existing["avg_lol"] = round((existing["avg_lol"] * existing["_prev_count"] + avg_lol * count) / total, 0) if avg_lol is not None else existing["avg_lol"]
                    existing["_prev_count"] = total
                else:
                    po_int_dict[part_name] = {
                        "path_count": count,
                        "worst_s": worst_s,
                        "avg_s": avg_s,
                        "worst_pct": worst_pct,
                        "avg_lol": avg_lol,
                        "_prev_count": count,
                    }

            # Process partition internals (same-leaf, no clock filter)
            for row in int_same_rows:
                sp_part, ep_part, lclk, cclk, count, worst_s, avg_s, worst_pct, avg_lol = row
                if not sp_part:
                    continue
                po_int_total += count
                _merge_po_int(sp_part, count, worst_s, avg_s, worst_pct, avg_lol)

            # Process INT_C2C (different-leaf, with clock filters)
            for row in int_c2c_rows:
                sp_part, ep_part, lclk, cclk, count, worst_s, avg_s, worst_pct, avg_lol = row
                if not sp_part:
                    continue
                known_partition_names.update(p for p in (sp_part, ep_part) if p)
                filters = [f"StartPin:(^|/){sp_part}/.*", f"EndPin:(^|/){ep_part}/.*"]
                if lclk:
                    filters.append(f"LaunchClk:{lclk}")
                if cclk:
                    filters.append(f"CaptureClk:{cclk}")
                int_c2c_total += count
                int_c2c_buckets.append({
                    "priority": 80,
                    "filters": filters,
                    "classification": "CLASSIF_FCT",
                    "tag": "TAG_PO",
                    "description": f"{sp_part}->{ep_part}: {lclk}->{cclk} ({count} paths, worst {worst_s}ps, avg {avg_s}ps, avg_lol={avg_lol})",
                    "auto": True,
                    "path_count": count,
                    "section": "INT C2C",
                })

            # ── Auto-bucket 1b: Remaining INT paths (not INT_AllChildren) ──
            # These may have child_int_type like INT_SomeChildren or NULL.
            # Same-partition: merge into partition internals (no clock split).
            # Cross-partition: group by partition pair + clock domain.
            # Use leaf_depth-aware partition extraction (n-2 for memstack, n-1 otherwise).
            if leaf_depth > 1:
                sp_1b = _partition_expr("startpoint")
                ep_1b = _partition_expr("endpoint")
            else:
                sp_1b = _partition_expr("startpoint", "driver_partition")
                ep_1b = _partition_expr("endpoint", "receiver_partition")

            other_int_same_rows = con.execute(f"""
                SELECT
                    ({sp_1b}) as sp_part,
                    ({ep_1b}) as ep_part,
                    COUNT(*) as path_count,
                    ROUND(MIN(slack), 1) as worst_slack,
                    ROUND(AVG(slack), 1) as avg_slack,
                    ROUND(MIN(clock_percentage), 1) as worst_clock_pct,
                    ROUND(AVG(levels_of_logic), 0) as avg_lol
                FROM {source}
                WHERE {where}
                  AND int_ext = 'INT'
                  AND NOT ({int_exclude_cond})
                  AND ({sp_1b}) = ({ep_1b})
                GROUP BY sp_part, ep_part
                ORDER BY path_count DESC
            """, params).fetchall()
            for row in other_int_same_rows:
                sp_part, ep_part, count, worst_s, avg_s, worst_pct, avg_lol = row
                if not sp_part:
                    continue
                po_int_total += count
                _merge_po_int(sp_part, count, worst_s, avg_s, worst_pct, avg_lol)

            other_int_c2c_rows = con.execute(f"""
                SELECT
                    ({sp_1b}) as sp_part,
                    ({ep_1b}) as ep_part,
                    launch_clock, capture_clock,
                    COUNT(*) as path_count,
                    ROUND(MIN(slack), 1) as worst_slack,
                    ROUND(AVG(slack), 1) as avg_slack,
                    ROUND(MIN(clock_percentage), 1) as worst_clock_pct,
                    ROUND(AVG(levels_of_logic), 0) as avg_lol
                FROM {source}
                WHERE {where}
                  AND int_ext = 'INT'
                  AND NOT ({int_exclude_cond})
                  AND ({sp_1b}) != ({ep_1b})
                GROUP BY sp_part, ep_part, launch_clock, capture_clock
                ORDER BY path_count DESC
            """, params).fetchall()
            for row in other_int_c2c_rows:
                sp_part, ep_part, lclk, cclk, count, worst_s, avg_s, worst_pct, avg_lol = row
                if not sp_part:
                    continue
                known_partition_names.update(p for p in (sp_part, ep_part) if p)
                filters = [f"StartPin:(^|/){sp_part}/.*", f"EndPin:(^|/){ep_part}/.*"]
                if lclk:
                    filters.append(f"LaunchClk:{lclk}")
                if cclk:
                    filters.append(f"CaptureClk:{cclk}")
                int_c2c_total += count
                int_c2c_buckets.append({
                    "priority": 80,
                    "filters": filters,
                    "classification": "CLASSIF_FCT",
                    "tag": "TAG_PO",
                    "description": f"INT C2C {sp_part}->{ep_part}: {lclk}->{cclk} ({count} paths, worst {worst_s}ps/{worst_pct}%, avg LoL {avg_lol})",
                    "auto": True,
                    "path_count": count,
                    "section": "INT C2C",
                })

        # Convert po_int_dict to po_int_buckets list
        po_int_buckets = []
        if persona != "po":
            for part_name, stats in sorted(po_int_dict.items(), key=lambda x: -x[1]["path_count"]):
                po_int_buckets.append({
                    "priority": 95,
                    "filters": [f"StartPin:(^|/){part_name}/.*", f"EndPin:(^|/){part_name}/.*"],
                    "classification": "CLASSIF_PARs_INT",
                    "tag": "TAG_PO",
                    "description": f"{part_name} partition_internals ({stats['path_count']} paths, worst {stats['worst_s']}ps, avg {stats['avg_s']}ps, avg_lol={stats['avg_lol']})",
                    "auto": True,
                    "path_count": stats["path_count"],
                    "section": "PARTITION INTERNALS",
                })

        # Resolve the real partition name used in pin paths.
        # For memstack (leaf_depth=2), this avoids using wrapper-only n-1 names like
        # mc_cluster and instead targets the real leaf partition (parmccore_0, etc.).
        sp_real_part = _partition_expr("startpoint", "driver_partition")
        ep_real_part = _partition_expr("endpoint", "receiver_partition")

        def _pin_filter(column_name, pin_name, is_port):
            if not pin_name:
                return None
            if is_port:
                base_name = re.sub(r"\[[^\]]+\]$", "", pin_name)
                return f"{column_name}:^{re.escape(base_name)}(\\[[^\\]]+\\])?$"
            if pin_name not in known_partition_names:
                return f"{column_name}:^{re.escape(pin_name)}$"
            return f"{column_name}:(^|/){re.escape(pin_name)}/.*"

        def _ext_group_label(group_name):
            if group_name == "__INPUT_PORTS__":
                return "INPUT PORTS"
            if group_name == "__OUTPUT_PORTS__":
                return "OUTPUT PORTS"
            if group_name == "__FEED_THROUGH__":
                return "FEED_THROUGH"
            return group_name

        # ── Auto-bucket 2: milestone waiver bucket (optional) ──
        waiver_buckets = []
        waiver_total = 0
        waiver_rule = _waiver_rule_for_milestone(milestone, mode)
        if waiver_rule:
            waive_row = con.execute(f"""
                SELECT
                    COUNT(*) as path_count,
                    ROUND(MIN(slack), 1) as worst_slack,
                    ROUND(AVG(slack), 1) as avg_slack,
                    ROUND(MIN(clock_percentage), 1) as worst_clock_pct,
                    ROUND(AVG(levels_of_logic), 0) as avg_lol
                FROM {source}
                WHERE {where}
                  AND {waiver_rule['sql']}
            """, params).fetchone()
            if waive_row and waive_row[0]:
                count, worst_s, avg_s, worst_pct, avg_lol = waive_row
                waiver_total = count
                if mode == "setup":
                    desc = f"{waiver_rule['section']} {waiver_rule['label']} ({count} paths, worst {worst_s}ps/{worst_pct}%, avg {avg_s}ps, avg_lol={avg_lol})"
                else:
                    desc = f"{waiver_rule['section']} {waiver_rule['label']} ({count} paths, worst {worst_s}ps, avg {avg_s}ps, avg_lol={avg_lol})"
                waiver_buckets.append({
                    "priority": 1,
                    "filters": [waiver_rule["filter"]],
                    "classification": waiver_rule["classification"],
                    "description": desc,
                    "auto": True,
                    "path_count": count,
                    "section": waiver_rule["section"],
                })

        # ── Auto-bucket 3: PTECO candidates (tiny timing window 0-2%, NOT internal) ──
        pteco_buckets = []
        pteco_total = 0
        if persona != "po":
            pteco = con.execute(f"""
                SELECT
                    launch_clock, capture_clock,
                    ({sp_real_part}) as dpart,
                    ({ep_real_part}) as rpart,
                    {_is_port_expr('startpoint', 'start')} as d_is_port,
                    {_is_port_expr('endpoint', 'end')} as r_is_port,
                    COUNT(*) as path_count,
                    ROUND(MIN(slack), 1) as worst_slack,
                    ROUND(MIN(clock_percentage), 1) as worst_clock_pct
                FROM {source}
                WHERE {where}
                  AND clock_percentage >= 0 AND clock_percentage < 2
                  AND int_ext != 'INT'
                GROUP BY launch_clock, capture_clock, dpart, rpart, d_is_port, r_is_port
                ORDER BY path_count DESC
            """, params)
            for row in pteco.fetchall():
                lclk, cclk, dpart, rpart, d_is_port, r_is_port, count, worst_s, worst_pct = row
                pteco_total += count
                desc = f"PTECO: {lclk}->{cclk} {dpart}->{rpart} ({count} paths, worst {worst_s}ps, {worst_pct}% window)"
                filters = [f"LaunchClk:{lclk}", f"CaptureClk:{cclk}"]
                d_filter = _pin_filter("StartPin", dpart, d_is_port)
                r_filter = _pin_filter("EndPin", rpart, r_is_port)
                if d_filter:
                    filters.append(d_filter)
                if r_filter:
                    filters.append(r_filter)
                pteco_buckets.append({
                    "priority": 50,
                    "filters": filters,
                    "classification": "CLASSIF_OPT",
                    "tag": "TAG_PTECO",
                    "description": desc,
                    "auto": True,
                    "path_count": count,
                    "section": "PTECO",
                })

        # ── Auto-bucket 4: EXT paths → group by real partition crossing + clock domain ──
        ext_buckets = []
        ext_total = 0
        if persona != "po":
            ext_paths = con.execute(f"""
                SELECT
                    CASE
                        WHEN {_is_port_expr('startpoint', 'start')} THEN
                            CASE
                                WHEN path_group = 'FEED_THROUGH' THEN '__FEED_THROUGH__'
                                ELSE '__INPUT_PORTS__'
                            END
                        ELSE ({sp_real_part})
                    END as sp_part,
                    CASE
                        WHEN {_is_port_expr('endpoint', 'end')} THEN
                            CASE
                                WHEN path_group = 'FEED_THROUGH' THEN '__FEED_THROUGH__'
                                ELSE '__OUTPUT_PORTS__'
                            END
                        ELSE ({ep_real_part})
                    END as ep_part,
                    {_is_port_expr('startpoint', 'start')} as sp_is_port,
                    {_is_port_expr('endpoint', 'end')} as ep_is_port,
                    COUNT(*) as path_count,
                    COUNT(DISTINCT COALESCE(launch_clock, '') || '->' || COALESCE(capture_clock, '')) as clock_pairs,
                    ROUND(MIN(slack), 1) as worst_slack,
                    ROUND(AVG(slack), 1) as avg_slack,
                    ROUND(MIN(clock_percentage), 1) as worst_clock_pct,
                    ROUND(AVG(levels_of_logic), 0) as avg_lol
                FROM {source}
                WHERE {where}
                  AND int_ext = 'EXT'
                  AND (clock_percentage IS NULL OR clock_percentage < 0 OR clock_percentage >= 2)
                GROUP BY sp_part, ep_part, sp_is_port, ep_is_port
                ORDER BY path_count DESC
            """, params)
            for row in ext_paths.fetchall():
                sp_part, ep_part, sp_is_port, ep_is_port, count, clock_pairs, worst_s, avg_s, worst_pct, avg_lol = row
                if not sp_part:
                    continue
                ext_total += count
                # Determine crossing description
                sp_label = _ext_group_label(sp_part)
                ep_label = _ext_group_label(ep_part)
                if sp_label == ep_label:
                    crossing = sp_label
                else:
                    crossing = f"{sp_label}->{ep_label}"

                filters = []
                if sp_is_port and ep_is_port:
                    filters.append("PathGroup:FEED_THROUGH")
                else:
                    if sp_is_port:
                        filters.append("PathGroup:INPUT_PATHS")
                    else:
                        sp_filter = _pin_filter("StartPin", sp_part, sp_is_port)
                        if sp_filter:
                            filters.append(sp_filter)

                    if ep_is_port:
                        filters.append("PathGroup:OUTPUT_PATHS")
                    else:
                        ep_filter = _pin_filter("EndPin", ep_part, ep_is_port)
                        if ep_filter:
                            filters.append(ep_filter)

                ext_buckets.append({
                    "priority": 85,
                    "filters": filters,
                    "classification": "CLASSIF_FCT",
                    "tag": "TAG_PO",
                    "description": f"EXT {crossing} ({count} paths, {clock_pairs} clk pairs, worst {worst_s}ps, avg {avg_s}ps, avg_lol={avg_lol})",
                    "auto": True,
                    "path_count": count,
                    "section": "EXT C2C",
                })

        # ── Auto-bucket 5: Top-level input-port paths in the remaining pool ──
        # These often start from ports like fdfx_security_* and will never match
        # partition-based StartPin filters because they are not hierarchical cell paths.
        pre_remaining_where = (f"{where}"
            f" AND NOT (int_ext = 'INT')"
            f" AND NOT (int_ext = 'EXT')"
            f" AND NOT (clock_percentage >= 0 AND clock_percentage < 2)")

        input_port_buckets = []
        input_port_total = 0
        if persona != "po":
            input_port_paths = con.execute(f"""
                SELECT
                    CASE
                        WHEN startpoint LIKE 'fdfx_security_%' THEN 'fdfx_security_*'
                        ELSE split_part(startpoint, '/', 1)
                    END as sp_port_group,
                    COUNT(*) as path_count,
                    ROUND(MIN(slack), 1) as worst_slack,
                    ROUND(AVG(slack), 1) as avg_slack,
                    ROUND(AVG(levels_of_logic), 0) as avg_lol
                FROM {source}
                WHERE {pre_remaining_where}
                  AND {_is_port_expr('startpoint', 'start')}
                GROUP BY sp_port_group
                ORDER BY path_count DESC
            """, params)
            for row in input_port_paths.fetchall():
                sp_port_group, count, worst_s, avg_s, avg_lol = row
                if not sp_port_group:
                    continue
                if sp_port_group == 'fdfx_security_*':
                    sp_filter = "StartPin:^fdfx_security_.*$"
                else:
                    sp_filter = f"StartPin:^{re.escape(sp_port_group)}$"
                filters = [sp_filter]
                input_port_total += count
                input_port_buckets.append({
                    "priority": 90,
                    "filters": filters,
                    "classification": "CLASSIF_CONS",
                    "tag": "TAG_CONS",
                    "description": f"INPUT PORTS {sp_port_group} ({count} paths, worst {worst_s}ps, avg {avg_s}ps, avg_lol={avg_lol})",
                    "auto": True,
                    "path_count": count,
                    "section": "INPUT PORTS",
                })

        _enrich_bucket_descriptions(con, source, where, params, waiver_buckets, mode)
        _enrich_bucket_descriptions(con, source, where, params, po_int_buckets, mode)
        _enrich_bucket_descriptions(con, source, where, params, int_c2c_buckets, mode)
        _enrich_bucket_descriptions(con, source, where, params, ext_buckets, mode)

        # ── Remaining: actual paths not matched by any Python auto-bucket filter ──
        # This is intentionally filter-accurate rather than category-accurate so the
        # LLM sees any auto-bucket misses caused by bad regexes or over-coarse grouping.
        all_auto_buckets = (
            waiver_buckets
            + po_int_buckets
            + input_port_buckets
            + int_c2c_buckets
            + pteco_buckets
            + ext_buckets
        )
        remaining_where = _build_unmatched_where(where, all_auto_buckets, mode)
        remaining_where_sql = _build_unmatched_where(where_sql, all_auto_buckets, mode)
        remaining_view = "triage_remaining_paths"
        con.execute(
            f"CREATE OR REPLACE TEMP VIEW {remaining_view} AS "
            f"SELECT * FROM {source} WHERE {remaining_where_sql}"
        )
        remaining_count = con.execute(
            f"SELECT COUNT(*) FROM {remaining_view}"
        ).fetchone()[0]

        # Top groups by clock domain + partition crossing
        remaining_groups = con.execute(f"""
            SELECT
                launch_clock, capture_clock,
                int_ext, int_ext_child,
                driver_partition, receiver_partition,
                COUNT(*) as path_count,
                ROUND(MIN(slack), 1) as worst_slack,
                ROUND(AVG(slack), 1) as avg_slack,
                ROUND(MIN(clock_percentage), 1) as worst_clock_pct,
                ROUND(AVG(clock_percentage), 1) as avg_clock_pct,
                ROUND(AVG(levels_of_logic), 0) as avg_lol
            FROM {remaining_view}
            GROUP BY launch_clock, capture_clock, int_ext, int_ext_child,
                     driver_partition, receiver_partition
            ORDER BY path_count DESC
            LIMIT 60
        """)
        rem_grp_cols = [d[0] for d in remaining_groups.description]
        rem_grp_rows = [list(r) for r in remaining_groups.fetchall()]

        # Top startpoint prefixes in remaining paths
        sp_prefixes = con.execute(f"""
            SELECT
                SUBSTRING(startpoint, 1, POSITION('/' IN startpoint || '/')) as sp_prefix,
                COUNT(*) as cnt
            FROM {remaining_view}
            GROUP BY sp_prefix
            ORDER BY cnt DESC
            LIMIT 20
        """)
        sp_rows = [list(r) for r in sp_prefixes.fetchall()]

        # Top endpoint prefixes in remaining paths
        ep_prefixes = con.execute(f"""
            SELECT
                SUBSTRING(endpoint, 1, POSITION('/' IN endpoint || '/')) as ep_prefix,
                COUNT(*) as cnt
            FROM {remaining_view}
            GROUP BY ep_prefix
            ORDER BY cnt DESC
            LIMIT 20
        """)
        ep_rows = [list(r) for r in ep_prefixes.fetchall()]

        # 30 worst remaining paths for pattern analysis
        worst = con.execute(f"""
            SELECT
                slack, clock_percentage, launch_clock, capture_clock,
                int_ext, driver_partition, receiver_partition,
                levels_of_logic, startpoint, endpoint
            FROM {remaining_view}
            ORDER BY slack ASC
            LIMIT 30
        """)
        worst_cols = [d[0] for d in worst.description]
        worst_rows = [list(r) for r in worst.fetchall()]

        return {
            "block": block or os.path.basename(csv_path).split('.')[0],
            "run_label": run_label or csv_path,
            "mode": mode,
            "scope": {
                "persona": persona,
                "partition": partition,
                "note": scope_note,
            },
            "summary": {"columns": sum_cols, "rows": sum_rows},
            "auto_buckets": {
                "waiver": {"buckets": waiver_buckets, "total_paths": waiver_total, "milestone": milestone},
                "po_int": {"buckets": po_int_buckets, "total_paths": po_int_total},
                "pteco": {"buckets": pteco_buckets, "total_paths": pteco_total},
                "int_c2c": {"buckets": int_c2c_buckets, "total_paths": int_c2c_total},
                "ext": {"buckets": ext_buckets, "total_paths": ext_total},
                "input_ports": {"buckets": input_port_buckets, "total_paths": input_port_total},
                "note": (
                    "Milestone waiver buckets (when enabled), INT, EXT, PTECO, and top-level input-port paths are auto-bucketed by Python. Remaining paths go to the LLM."
                    if persona != "po"
                    else f"PO mode leaves internal paths for partition '{partition}' unbucketed so the LLM can drill into that partition only."
                ),
            },
            "remaining_c2c_ext": {
                "total_paths": remaining_count,
                "pct_of_total": round(100 * remaining_count / total_failing, 1) if total_failing else 0,
                "remaining_view": remaining_view,
                "query_tool": "query_timing_db",
                "query_examples": [
                    f"SELECT slack, launch_clock, capture_clock, startpoint, endpoint FROM {remaining_view} ORDER BY slack ASC LIMIT 50",
                    f"SELECT split_part(startpoint, '/', 1) AS sp_root, split_part(endpoint, '/', 1) AS ep_root, COUNT(*) AS path_count, ROUND(MIN(slack), 1) AS worst_slack FROM {remaining_view} GROUP BY sp_root, ep_root ORDER BY path_count DESC LIMIT 40",
                ],
                "groups": {"columns": rem_grp_cols, "rows": rem_grp_rows},
                "startpoint_prefixes": sp_rows,
                "endpoint_prefixes": ep_rows,
                "worst_paths": {"columns": worst_cols, "rows": worst_rows},
                "note": (
                    "These are the actual residual failing paths after Python auto-buckets are applied. Query the remaining_view directly for pass-2 LLM bucketing."
                    if persona != "po"
                    else f"These are the internal failing paths still remaining within partition '{partition}' after PO-scoped Python auto-buckets are applied. Query the remaining_view directly for pass-2 PO bucketing."
                ),
            },
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

        Format:
            <priority> <filter&&filter&&...> CLASSIF_xxx [OWNER_xxx] [free text description]
        All fields on one line. Description at end is displayed in timinglite UI.
        Section headers are written as plain text lines so Timing Lite shows them as labels.
    """
    # Define section order for grouping buckets
    SECTION_ORDER = [
        "WAIVE0P5",
        "WAIVE0P8",
        "PARTITION INTERNALS",
        "INPUT PORTS",
        "EXT C2C",
        "INT C2C",
        "PTECO",
        "OTHER",
    ]

    path_type = "max" if mode == "setup" else "min"

    def _bucket_to_line(bucket):
        priority = bucket.get("priority", 1)
        raw_filters = bucket.get("filters", [])
        # Remove any PathType filters provided by Claude (we add it ourselves)
        raw_filters = [f for f in raw_filters if not f.startswith("PathType:")]
        filters = [f"PathType:{path_type}"] + [_sanitize_filter_regex(f) for f in raw_filters]
        classification = bucket.get("classification", "")
        filter_str = "&&".join(filters)
        desc = bucket.get("description", "")
        line = f"{priority} {filter_str} {classification}"
        if desc:
            line += f" {desc}"
        return line

    # Group buckets by section
    from collections import OrderedDict
    sections = OrderedDict()
    for s in SECTION_ORDER:
        sections[s] = []
    for bucket in buckets:
        section = bucket.get("section", "OTHER")
        if section not in sections:
            sections[section] = []
        sections[section].append(bucket)

    lines = []
    for section_name, section_buckets in sections.items():
        if not section_buckets:
            continue
        # Add section header (plain text line, no # prefix — timinglite shows it as a label)
        lines.append(f"{section_name}")
        for bucket in section_buckets:
            lines.append(_bucket_to_line(bucket))

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
    "Slack": "slack",
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

    def col_or_null(standard, *alternatives, cast_to=None, strip_pct=False):
        for alt in (standard,) + alternatives:
            if alt in csv_cols:
                expr = f'"{alt}"'
                if strip_pct:
                    expr = f"REPLACE({expr}, '%', '')"
                if cast_to and ('VARCHAR' in csv_types.get(alt, '').upper() or strip_pct):
                    expr = f'TRY_CAST({expr} AS {cast_to})'
                return f'{expr} AS {standard}'
        return f"NULL AS {standard}"

    aliases = [
        col_or_null("slack", "normal_slack", cast_to="DOUBLE"),
        col_or_null("clock_percentage", cast_to="DOUBLE", strip_pct=True),
        col_or_null("period", "start_clock_period", cast_to="DOUBLE"),
        col_or_null("startpoint", "start_pin"),
        col_or_null("endpoint", "end_pin"),
        col_or_null("launch_clock", "start_clock"),
        col_or_null("capture_clock", "end_clock"),
        col_or_null("path_group"),
        col_or_null("int_ext"),
        col_or_null("int_ext_child"),
        col_or_null("child_int_type"),
        col_or_null("thru_children"),
        col_or_null("driver_partition", "start_par"),
        col_or_null("receiver_partition", "end_par"),
        col_or_null("levels_of_logic", "number_data_cells", cast_to="INTEGER"),
        col_or_null("path_type", "path_delay_type"),
    ]
    return f"(SELECT {', '.join(aliases)} FROM {raw_src}) AS csv_data"


def _sql_literal(value):
    if value is None:
        return "NULL"
    return "'" + str(value).replace("'", "''") + "'"


def _waiver_rule_for_milestone(milestone, mode):
    milestone_key = (milestone or "").strip().lower()
    milestone_rules = WAIVER_MILESTONE_RULES.get(milestone_key)
    if not milestone_rules:
        return None
    mode_rules = milestone_rules.get(mode)
    if not mode_rules:
        return None
    milestone_tag = milestone_key.upper().replace(".", "")
    return {
        "classification": f"CLASSIF_WAIVE{milestone_tag}",
        "section": f"WAIVE{milestone_tag}",
        **mode_rules,
    }


def _bucket_has_filter(bucket, prefix):
    return any(str(filt).startswith(prefix) for filt in bucket.get("filters", []))


def _format_bucket_mix(rows, total):
    parts = []
    for label, count in rows:
        if not label or not count:
            continue
        pct = round((count * 100.0) / total)
        parts.append(f"{label} {pct}%")
    return ", ".join(parts)


def _bucket_hint(summary):
    total = summary["total"]
    if not total:
        return ""

    notes = []
    deep_ratio = summary["deep_logic"] / total
    shallow_ratio = summary["shallow_logic"] / total
    worst_pct = summary["worst_clock_pct"]

    if summary["feedthrough"] / total >= 0.5:
        notes.append("feedthrough-heavy")
    elif summary["input_paths"] / total >= 0.8:
        notes.append("mostly input-driven")
    elif summary["output_paths"] / total >= 0.8:
        notes.append("mostly output-driven")

    if deep_ratio >= 0.5:
        notes.append("deep-logic dominated")
    elif shallow_ratio >= 0.5:
        if worst_pct is not None and worst_pct <= -50:
            notes.append("shallow but severe")
        else:
            notes.append("shallow-logic dominated")

    if summary["path_group_count"] and summary["path_group_count"] > 3:
        notes.append(f"mixed {summary['path_group_count']} path groups")

    return ", ".join(notes)


def _enrich_bucket_descriptions(con, source, base_where, params, buckets, mode):
    """Append lightweight per-bucket insight derived from the matched paths."""
    for bucket in buckets:
        conditions = _bucket_sql_conditions(bucket, mode)
        if not conditions:
            continue

        full_where = f"{base_where} AND {' AND '.join(conditions)}"
        summary_row = con.execute(f"""
            SELECT
                COUNT(*) as total_paths,
                COUNT(DISTINCT COALESCE(path_group, '')) as path_group_count,
                COUNT(DISTINCT COALESCE(launch_clock, '') || '->' || COALESCE(capture_clock, '')) as clock_pair_count,
                SUM(CASE WHEN levels_of_logic >= 25 THEN 1 ELSE 0 END) as deep_logic_paths,
                SUM(CASE WHEN levels_of_logic <= 5 THEN 1 ELSE 0 END) as shallow_logic_paths,
                SUM(CASE WHEN path_group = 'INPUT_PATHS' THEN 1 ELSE 0 END) as input_paths,
                SUM(CASE WHEN path_group = 'OUTPUT_PATHS' THEN 1 ELSE 0 END) as output_paths,
                SUM(CASE WHEN path_group = 'FEED_THROUGH' THEN 1 ELSE 0 END) as feedthrough_paths,
                ROUND(MIN(clock_percentage), 1) as worst_clock_pct
            FROM {source}
            WHERE {full_where}
        """, params).fetchone()

        if not summary_row or not summary_row[0]:
            continue

        summary = {
            "total": summary_row[0],
            "path_group_count": summary_row[1] or 0,
            "clock_pair_count": summary_row[2] or 0,
            "deep_logic": summary_row[3] or 0,
            "shallow_logic": summary_row[4] or 0,
            "input_paths": summary_row[5] or 0,
            "output_paths": summary_row[6] or 0,
            "feedthrough": summary_row[7] or 0,
            "worst_clock_pct": summary_row[8],
        }

        top_groups = con.execute(f"""
            SELECT COALESCE(path_group, 'NA') as path_group, COUNT(*) as path_count
            FROM {source}
            WHERE {full_where}
            GROUP BY path_group
            ORDER BY path_count DESC, path_group
            LIMIT 2
        """, params).fetchall()

        additions = []
        group_mix = _format_bucket_mix(top_groups, summary["total"])
        if group_mix:
            additions.append(f"groups={group_mix}")

        if not (_bucket_has_filter(bucket, "LaunchClk:") and _bucket_has_filter(bucket, "CaptureClk:")):
            top_clocks = con.execute(f"""
                SELECT COALESCE(launch_clock, 'NA') || '->' || COALESCE(capture_clock, 'NA') as clock_pair,
                       COUNT(*) as path_count
                FROM {source}
                WHERE {full_where}
                GROUP BY clock_pair
                ORDER BY path_count DESC, clock_pair
                LIMIT 2
            """, params).fetchall()
            clock_mix = _format_bucket_mix(top_clocks, summary["total"])
            if clock_mix and summary["clock_pair_count"] > 1:
                additions.append(f"clock_mix={clock_mix}")

        hint = _bucket_hint(summary)
        if hint:
            additions.append(f"hint={hint}")

        if additions:
            bucket["description"] = f"{bucket['description']}; " + "; ".join(additions)


def _numeric_filter_condition(column_name, expression):
    match = re.match(r"^\s*(<=|>=|=|<|>)\s*(-?\d+(?:\.\d+)?)\s*$", str(expression))
    if not match:
        return None
    operator, value = match.groups()
    return f"{column_name} {operator} {value}"


def _bucket_sql_conditions(bucket, mode):
    path_type = "max" if mode == "setup" else "min"
    raw_filters = [f for f in bucket.get("filters", []) if not f.startswith("PathType:")]
    filters = [f"PathType:{path_type}"] + [_sanitize_filter_regex(f) for f in raw_filters]

    conditions = []
    for filt in filters:
        if ':' not in filt:
            continue
        col_name, regex_val = filt.split(':', 1)
        db_col = FILTER_COL_MAP.get(col_name, col_name)
        if db_col == "path_type":
            conditions.append(f"path_type = {_sql_literal(path_type)}")
        elif db_col in {"clock_percentage", "slack"}:
            numeric_condition = _numeric_filter_condition(db_col, regex_val)
            if numeric_condition:
                conditions.append(numeric_condition)
        else:
            safe_regex = regex_val.replace("'", "''")
            conditions.append(f"regexp_matches({db_col}, '{safe_regex}')")
    return conditions


def _build_unmatched_where(base_where, buckets, mode):
    matched_conditions = []
    for bucket in buckets:
        conditions = _bucket_sql_conditions(bucket, mode)
        if conditions:
            matched_conditions.append(f"({' AND '.join(conditions)})")
    if matched_conditions:
        return f"{base_where} AND NOT ({' OR '.join(matched_conditions)})"
    return base_where


def review_auto_buckets(con, mode, block=None, run_label=None, csv_path=None, bucket_indexes=None, max_samples=3):
    """Return context for current Python auto-buckets so the LLM can assess them."""
    try:
        if csv_path:
            source = _csv_source_with_aliases(con, csv_path)
            base_where = "slack < 0"
            params = []
        else:
            source = "paths"
            base_where = "block = ? AND run_label = ? AND mode = ? AND slack < 0"
            params = [block, run_label, mode]

        scope_sql = _current_po_scope_sql(block=block)
        if scope_sql:
            base_where = _append_scope_filter(base_where, scope_sql)

        if bucket_indexes is not None:
            selected_indexes = sorted(set(bucket_indexes))
            selected = set(selected_indexes)
            review_mode = "explicit_indexes"
            review_limit = None
        else:
            review_limit = 40
            selected_indexes = [
                index for index, _bucket in sorted(
                    enumerate(_auto_buckets_for_export),
                    key=lambda item: item[1].get("path_count", 0),
                    reverse=True,
                )[:review_limit]
            ]
            selected = set(selected_indexes)
            review_mode = "largest_buckets"
        reviews = []
        max_samples = max(1, min(int(max_samples or 3), 10))

        for index, bucket in enumerate(_auto_buckets_for_export):
            if index not in selected:
                continue

            conditions = _bucket_sql_conditions(bucket, mode)
            if not conditions:
                reviews.append({
                    "bucket_index": index,
                    "section": bucket.get("section", "OTHER"),
                    "classification": bucket.get("classification", ""),
                    "current_description": bucket.get("description", ""),
                    "filters": bucket.get("filters", []),
                    "error": "no valid filters",
                })
                continue

            full_where = f"{base_where} AND {' AND '.join(conditions)}"
            summary_row = con.execute(f"""
                SELECT
                    COUNT(*) as total_paths,
                    ROUND(MIN(slack), 1) as worst_slack,
                    ROUND(AVG(slack), 1) as avg_slack,
                    ROUND(MIN(clock_percentage), 1) as worst_clock_pct,
                    ROUND(AVG(levels_of_logic), 1) as avg_lol,
                    COUNT(DISTINCT COALESCE(path_group, '')) as path_group_count,
                    COUNT(DISTINCT COALESCE(launch_clock, '') || '->' || COALESCE(capture_clock, '')) as clock_pair_count
                FROM {source}
                WHERE {full_where}
            """, params).fetchone()

            top_groups = con.execute(f"""
                SELECT COALESCE(path_group, 'NA') as path_group, COUNT(*) as path_count
                FROM {source}
                WHERE {full_where}
                GROUP BY path_group
                ORDER BY path_count DESC, path_group
                LIMIT 3
            """, params).fetchall()

            top_clocks = con.execute(f"""
                SELECT COALESCE(launch_clock, 'NA') || '->' || COALESCE(capture_clock, 'NA') as clock_pair,
                       COUNT(*) as path_count
                FROM {source}
                WHERE {full_where}
                GROUP BY clock_pair
                ORDER BY path_count DESC, clock_pair
                LIMIT 3
            """, params).fetchall()

            worst_paths_result = con.execute(f"""
                SELECT startpoint, endpoint, launch_clock, capture_clock,
                       path_group, slack, clock_percentage, levels_of_logic
                FROM {source}
                WHERE {full_where}
                ORDER BY slack ASC
                LIMIT {max_samples}
            """, params)
            sample_cols = [d[0] for d in worst_paths_result.description]
            sample_rows = [list(r) for r in worst_paths_result.fetchall()]

            reviews.append({
                "bucket_index": index,
                "section": bucket.get("section", "OTHER"),
                "classification": bucket.get("classification", ""),
                "current_description": bucket.get("description", ""),
                "filters": bucket.get("filters", []),
                "summary": {
                    "total_paths": summary_row[0] if summary_row else 0,
                    "worst_slack": summary_row[1] if summary_row else None,
                    "avg_slack": summary_row[2] if summary_row else None,
                    "worst_clock_pct": summary_row[3] if summary_row else None,
                    "avg_lol": summary_row[4] if summary_row else None,
                    "path_group_count": summary_row[5] if summary_row else 0,
                    "clock_pair_count": summary_row[6] if summary_row else 0,
                },
                "top_path_groups": [
                    {"path_group": row[0], "count": row[1]} for row in top_groups
                ],
                "top_clock_pairs": [
                    {"clock_pair": row[0], "count": row[1]} for row in top_clocks
                ],
                "worst_paths": {"columns": sample_cols, "rows": sample_rows},
            })

        return {
            "auto_bucket_count": len(_auto_buckets_for_export),
            "review_mode": review_mode,
            "review_limit": review_limit,
            "reviewed_bucket_count": len(reviews),
            "omitted_bucket_count": max(0, len(_auto_buckets_for_export) - len(reviews)),
            "selected_bucket_indexes": selected_indexes,
            "buckets": reviews,
        }
    except Exception as e:
        return {"error": str(e)}


def annotate_auto_buckets(annotations):
    """Append or replace LLM description text on the Python auto-buckets."""
    try:
        updated = []
        for annotation in annotations:
            bucket_index = annotation["bucket_index"]
            llm_description = annotation["llm_description"].strip()
            if bucket_index < 0 or bucket_index >= len(_auto_buckets_for_export):
                updated.append({"bucket_index": bucket_index, "error": "index out of range"})
                continue
            if not llm_description:
                updated.append({"bucket_index": bucket_index, "error": "empty llm_description"})
                continue

            bucket = _auto_buckets_for_export[bucket_index]
            base_desc = re.sub(r"; LLM description: .*?$", "", bucket.get("description", "")).rstrip()
            bucket["description"] = f"{base_desc}; LLM description: {llm_description}"
            updated.append({
                "bucket_index": bucket_index,
                "section": bucket.get("section", "OTHER"),
                "description": bucket["description"],
            })
        return {"updated": updated}
    except Exception as e:
        return {"error": str(e)}


def validate_buckets(con, buckets, block, run_label, mode, csv_path=None):
    """Test bucket filter coverage against actual failing paths.

    For each bucket, builds a SQL WHERE clause from its regex filters and counts
    how many failing paths it matches. Returns per-bucket match counts and the
    total unmatched path count with sample unmatched paths.
    """
    try:
        if csv_path:
            source = _csv_source_with_aliases(con, csv_path)
            base_where = "slack < 0"
            base_where_sql = base_where
            params = []
        else:
            source = "paths"
            base_where = "block = ? AND run_label = ? AND mode = ? AND slack < 0"
            base_where_sql = (
                f"block = {_sql_literal(block)} AND run_label = {_sql_literal(run_label)} "
                f"AND mode = {_sql_literal(mode)} AND slack < 0"
            )
            params = [block, run_label, mode]

        scope_sql = _current_po_scope_sql(block=block)
        if scope_sql:
            base_where = _append_scope_filter(base_where, scope_sql)
            base_where_sql = _append_scope_filter(base_where_sql, scope_sql)

        path_type = "max" if mode == "setup" else "min"

        # Get total failing
        total_row = con.execute(
            f"SELECT COUNT(*) FROM {source} WHERE {base_where}", params
        ).fetchone()
        total_failing = total_row[0]

        bucket_results = []

        for i, bucket in enumerate(buckets):
            conditions = _bucket_sql_conditions(bucket, mode)

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

        # Count unmatched paths
        unmatched_where = _build_unmatched_where(base_where, buckets, mode)
        unmatched_where_sql = _build_unmatched_where(base_where_sql, buckets, mode)
        unmatched_view = "triage_unmatched_paths"
        con.execute(
            f"CREATE OR REPLACE TEMP VIEW {unmatched_view} AS "
            f"SELECT * FROM {source} WHERE {unmatched_where_sql}"
        )

        unmatched_count = con.execute(
            f"SELECT COUNT(*) FROM {unmatched_view}"
        ).fetchone()[0]

        # Sample unmatched paths for debugging
        unmatched_sample = con.execute(f"""
            SELECT startpoint, endpoint, launch_clock, capture_clock,
                   driver_partition, receiver_partition, int_ext, slack,
                   clock_percentage, levels_of_logic
            FROM {unmatched_view}
            ORDER BY slack ASC
            LIMIT 30
        """)
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
            "unmatched_view": unmatched_view,
            "working_buckets": coverage_summary,
            "broken_buckets": broken_buckets,
            "unmatched_sample": {"columns": sample_cols, "rows": sample_rows},
            "query_examples": [
                f"SELECT slack, launch_clock, capture_clock, startpoint, endpoint FROM {unmatched_view} ORDER BY slack ASC LIMIT 50",
                f"SELECT split_part(startpoint, '/', 1) AS sp_root, split_part(endpoint, '/', 1) AS ep_root, COUNT(*) AS path_count, ROUND(MIN(slack), 1) AS worst_slack FROM {unmatched_view} GROUP BY sp_root, ep_root ORDER BY path_count DESC LIMIT 40",
            ],
            "hint": "Use query_timing_db on unmatched_view or the unmatched_sample to create additional buckets, then re-validate." if unmatched_count > 0 else "All paths covered!",
        }
    except Exception as e:
        return {"error": str(e)}


# Auto-buckets (PO_INT + PTECO) created by Python during triage — merged into export
_auto_buckets_for_export = []
_last_exported_bucket_path = None
_active_triage_scope = {}


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
        persona = tool_input.get("persona", "sto")
        partition = tool_input.get("partition")
        label = csv_path or f"{block}/{run_label}"
        console.print(f"\n[dim]Triaging {label} ({mode})...[/dim]\n")
        ldepth = BLOCKS.get(block, {}).get("leaf_depth", 1) if block else 1
        result = triage_timing_run(
            con,
            block,
            run_label,
            mode,
            csv_path=csv_path,
            leaf_depth=ldepth,
            milestone=tool_input.get("milestone"),
            persona=persona,
            partition=partition,
        )
        if "error" not in result:
            summary = result["summary"]["rows"][0] if result["summary"]["rows"] else []
            if summary:
                console.print(f"  [bold]{summary[0]}[/bold] failing paths, worst slack: [red]{summary[1]}ps[/red]")
                console.print(f"  {summary[3]} clock domain pairs, {summary[4]} partition crossings")
            auto = result.get("auto_buckets", {})
            auto_count = sum(len(auto.get(section, {}).get("buckets", [])) for section in ["waiver", "po_int", "input_ports", "int_c2c", "pteco", "ext"])
            remaining = result.get("remaining_c2c_ext", {}).get("total_paths", 0)
            console.print(f"  {auto_count} auto-buckets, {remaining} remaining paths\n")
        else:
            console.print(f"[red]{result['error']}[/red]")
        return json.dumps(result, default=str)

    elif tool_name == "export_bucket_file":
        global _last_exported_bucket_path
        block = tool_input["block"]
        run_label = tool_input["run_label"]
        mode = tool_input["mode"]
        output_path = tool_input["output_path"]
        llm_buckets = tool_input["buckets"]
        # Strip any auto-bucketed classifications the LLM created — Python handles those
        auto_classifs = {"CLASSIF_PO_INT", "Partition_Internals", "CLASSIF_PTECO", "EXT_C2C", "INT_C2C", "CLASSIF_PO_OPT", "CLASSIF_PARs_INT", "CLASSIF_WAIVE0P5", "CLASSIF_WAIVE0P8"}  # strip if LLM leaks old/wrong names
        filtered_llm = []
        stripped = 0
        for b in llm_buckets:
            classif = b.get("classification", "")
            if classif in auto_classifs:
                stripped += 1
            else:
                filtered_llm.append(b)
        if stripped:
            console.print(f"  [dim]Stripped {stripped} LLM-generated auto-bucketed classifications (Python handles those)[/dim]")
        # Tag LLM buckets with section if not already tagged
        for b in filtered_llm:
            if "section" not in b:
                b["section"] = "OTHER"
        # Merge: export groups by section, then by priority within each section
        all_buckets = filtered_llm + list(_auto_buckets_for_export)
        all_buckets.sort(key=lambda b: b.get('priority', 1), reverse=True)
        console.print(f"\n[dim]Generating bucket file: {output_path}[/dim]")
        console.print(f"  [dim]{len(filtered_llm)} LLM buckets + {len(_auto_buckets_for_export)} auto-buckets[/dim]\n")
        result = export_bucket_file(all_buckets, output_path, block, run_label, mode)
        _last_exported_bucket_path = result.get("path")
        console.print(f"  [bold green]Wrote {result['bucket_count']} buckets[/bold green] to {result['path']}")
        console.print(f"  [dim]Load in Timing Lite: timinglite.py --bucket {result['path']} <report>[/dim]\n")
        return json.dumps(result, default=str)

    elif tool_name == "validate_buckets":
        mode = tool_input["mode"]
        llm_buckets = tool_input["buckets"]
        block = tool_input.get("block")
        run_label = tool_input.get("run_label")
        csv_path = tool_input.get("csv_path")
        all_buckets = list(llm_buckets) + list(_auto_buckets_for_export)
        console.print(
            f"\n[dim]Validating {len(llm_buckets)} LLM buckets + {len(_auto_buckets_for_export)} auto-buckets against failing paths...[/dim]\n"
        )
        result = validate_buckets(con, all_buckets, block, run_label, mode, csv_path=csv_path)
        if "error" not in result:
            matched = result["total_matched_by_buckets"]
            total = result["total_failing"]
            unmatched = result["total_unmatched"]
            pct = result["unmatched_pct"]
            status = "[bold green]PASS[/bold green]" if result["meets_target"] else "[bold red]FAIL[/bold red]"
            console.print(f"  Coverage: {matched}/{total} paths matched ({100-pct:.1f}%)")
            console.print(f"  Unmatched: {unmatched} paths ({pct}%) — target <5% — {status}")
        else:
            console.print(f"[red]{result['error']}[/red]")
        return json.dumps(result, default=str)

    elif tool_name == "review_auto_buckets":
        result = review_auto_buckets(
            con,
            tool_input["mode"],
            block=tool_input.get("block"),
            run_label=tool_input.get("run_label"),
            csv_path=tool_input.get("csv_path"),
            bucket_indexes=tool_input.get("bucket_indexes"),
            max_samples=tool_input.get("max_samples", 3),
        )
        return json.dumps(result, default=str)

    elif tool_name == "annotate_auto_buckets":
        result = annotate_auto_buckets(tool_input["annotations"])
        if "error" not in result:
            console.print(f"\n[dim]Annotated {len([r for r in result['updated'] if 'error' not in r])} auto-buckets with LLM descriptions.[/dim]\n")
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
             "  python agent.py --triage --reports-dir /path/to/reports -m setup --existing-bucket ./buckets/d2d1_setup.bucket\n"
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
    parser.add_argument("--milestone", choices=["0p5", "0p8", "1p0"], help="Optional milestone waiver profile. 0p5 and 0p8 add waiver buckets; 1p0 disables waiver buckets.")
    parser.add_argument("--output", "-o", help="Output path for bucket file (default: ./buckets/<block>_<run>_<mode>.bucket)")
    parser.add_argument("--existing-bucket", help="Seed triage with an existing timinglite bucket file and update it for the current run")
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
        if args.existing_bucket and not args.triage:
            console.print("[red]--existing-bucket is only supported with --triage[/red]")
            sys.exit(1)

        if args.triage:
            if not args.mode:
                console.print("[red]--triage requires --mode (setup or hold)[/red]")
                sys.exit(1)
            persona = args.persona or 'sto'
            partition = args.partition
            if persona == 'po' and not partition:
                console.print("[red]--persona po requires --partition <partition_name>[/red]")
                sys.exit(1)
            # Determine CSV path for ad-hoc triage
            csv_path = None
            csv_selection_reason = None
            if args.reports_dir:
                resolved = resolve_triage_csv_path(
                    args.reports_dir,
                    args.mode,
                    persona=persona,
                    partition=partition,
                )
                if "error" in resolved:
                    console.print(f"[red]{resolved['error']}[/red]")
                    sys.exit(1)
                csv_path = resolved["csv_path"]
                csv_selection_reason = resolved.get("selection_reason")
            elif not args.block or not args.run:
                console.print("[red]--triage requires either (--block + --run) or --reports-dir[/red]")
                sys.exit(1)

            block_label = args.block or os.path.basename(csv_path or 'unknown').split('.')[0]
            run_label = args.run or csv_path or 'ad-hoc'
            output_path = args.output or f"./buckets/{block_label}_{args.mode}.bucket"
            existing_bucket_data = None

            if persona == 'po':
                output_path = args.output or f"./buckets/{partition}_{args.mode}.bucket"

            if csv_selection_reason:
                console.print(f"  [dim]Using {csv_selection_reason}: {csv_path}[/dim]")

            if args.existing_bucket:
                try:
                    existing_bucket_data = load_existing_bucket_file(args.existing_bucket)
                except (FileNotFoundError, ValueError) as exc:
                    console.print(f"[red]{exc}[/red]")
                    sys.exit(1)
                console.print(
                    f"  Loaded {existing_bucket_data['bucket_count']} existing buckets from {existing_bucket_data['path']}"
                )
                if existing_bucket_data["skipped_line_count"]:
                    console.print(
                        f"  [dim]Skipped {existing_bucket_data['skipped_line_count']} non-bucket lines while parsing the seed file[/dim]"
                    )

            # Pre-call triage_timing_run in Python (avoids LLM path typos & saves a tool round-trip)
            console.print(f"\n[dim]Running triage analysis...[/dim]")
            ldepth = BLOCKS.get(block_label, {}).get("leaf_depth", 1) if block_label else 1
            _active_triage_scope.clear()
            _active_triage_scope.update({
                "persona": persona,
                "partition": partition,
                "block": block_label,
                "leaf_depth": ldepth,
            })
            triage_data = triage_timing_run(
                con,
                block_label,
                run_label,
                args.mode,
                csv_path=csv_path,
                leaf_depth=ldepth,
                milestone=args.milestone,
                persona=persona,
                partition=partition,
            )
            if "error" in triage_data:
                console.print(f"[red]Triage failed: {triage_data['error']}[/red]")
                sys.exit(1)

            summary = triage_data["summary"]["rows"][0] if triage_data["summary"]["rows"] else []
            if summary:
                console.print(f"  [bold]{summary[0]}[/bold] failing paths, worst slack: [red]{summary[1]}ps[/red]")
            auto = triage_data.get("auto_buckets", {})
            waiver_info = auto.get("waiver", {})
            waiver_buckets = waiver_info.get("buckets", [])
            waiver_count = waiver_info.get("total_paths", 0)
            waiver_milestone = waiver_info.get("milestone")
            waiver_section = waiver_buckets[0].get("section", f"WAIVE{str(waiver_milestone).upper().replace('.', '')}") if waiver_buckets else None
            po_int_buckets = auto.get("po_int", {}).get("buckets", [])
            pteco_buckets = auto.get("pteco", {}).get("buckets", [])
            int_c2c_buckets = auto.get("int_c2c", {}).get("buckets", [])
            ext_buckets = auto.get("ext", {}).get("buckets", [])
            input_port_buckets = auto.get("input_ports", {}).get("buckets", [])
            po_int_count = auto.get("po_int", {}).get("total_paths", 0)
            pteco_count = auto.get("pteco", {}).get("total_paths", 0)
            int_c2c_count = auto.get("int_c2c", {}).get("total_paths", 0)
            ext_count = auto.get("ext", {}).get("total_paths", 0)
            input_port_count = auto.get("input_ports", {}).get("total_paths", 0)
            remaining = triage_data.get("remaining_c2c_ext", {}).get("total_paths", 0)
            auto_total = waiver_count + po_int_count + input_port_count + int_c2c_count + pteco_count + ext_count
            waiver_console = f"{waiver_count} {waiver_section} ({len(waiver_buckets)} buckets) + " if waiver_buckets else ""
            waiver_prompt_line = f"  - {waiver_count} {waiver_section} ({len(waiver_buckets)} buckets)\n" if waiver_buckets else ""
            console.print(f"  Auto-bucketed: {waiver_console}{po_int_count} Partition_Internals ({len(po_int_buckets)} buckets) + {input_port_count} INPUT PORTS ({len(input_port_buckets)} buckets) + {int_c2c_count} INT_C2C ({len(int_c2c_buckets)} buckets) + {ext_count} EXT ({len(ext_buckets)} buckets) + {pteco_count} PTECO ({len(pteco_buckets)} buckets)")
            console.print(f"  Remaining for LLM: {remaining} paths\n")

            # Store exported auto-buckets for merging at export time.
            _auto_buckets_for_export.clear()
            _auto_buckets_for_export.extend(waiver_buckets)
            _auto_buckets_for_export.extend(po_int_buckets)
            _auto_buckets_for_export.extend(input_port_buckets)
            _auto_buckets_for_export.extend(int_c2c_buckets)
            _auto_buckets_for_export.extend(pteco_buckets)
            _auto_buckets_for_export.extend(ext_buckets)

            # Only send the actual residual set to the LLM after Python auto-buckets are applied.
            llm_data = {
                "block": triage_data.get("block"),
                "mode": triage_data.get("mode"),
                "scope": triage_data.get("scope"),
                "summary": triage_data.get("summary"),
                "auto_bucket_summary": {
                    "waiver_milestone": waiver_milestone,
                    "waiver_paths": waiver_count,
                    "waiver_buckets": len(waiver_buckets),
                    "partition_internals_paths": po_int_count,
                    "partition_internals_buckets": len(po_int_buckets),
                    "input_port_paths": input_port_count,
                    "input_port_buckets": len(input_port_buckets),
                    "int_c2c_paths": int_c2c_count,
                    "int_c2c_buckets": len(int_c2c_buckets),
                    "ext_paths": ext_count,
                    "ext_buckets": len(ext_buckets),
                    "pteco_paths": pteco_count,
                    "pteco_buckets": len(pteco_buckets),
                    "note": "Python handles the obvious first-pass buckets, including milestone waiver buckets when enabled. Pass 2 should bucket only the residual set left after those filters are applied.",
                },
                "remaining_c2c_ext": triage_data.get("remaining_c2c_ext"),
            }
            triage_json = json.dumps(llm_data, default=str)

            # Build validate/export params string so LLM doesn't mistype paths
            validate_params = f"mode='{args.mode}'"
            export_params = f"block='{block_label}', run_label='{run_label}', mode='{args.mode}', output_path='{output_path}'"
            if csv_path:
                validate_params += f", csv_path='{csv_path}'"
            else:
                validate_params += f", block='{block_label}', run_label='{run_label}'"

            existing_bucket_prompt = ""
            if existing_bucket_data:
                existing_bucket_json = json.dumps(existing_bucket_data, default=str)
                existing_bucket_prompt = (
                    f"\nYou are updating an existing bucket file instead of starting from scratch.\n"
                    f"Seed bucket file: {existing_bucket_data['path']}\n"
                    f"Parsed seed buckets (already converted to current classification names when needed):\n"
                    f"{existing_bucket_json}\n\n"
                    f"Update rules:\n"
                    f"- Start from these seed buckets for your first validation pass.\n"
                    f"- Keep buckets that still match the new run and still represent a distinct STO-owned root cause.\n"
                    f"- Repair or retarget buckets that now have 0 matches or overly broad matches.\n"
                    f"- Remove stale buckets that no longer apply.\n"
                    f"- Add new buckets for any new residual failing-path patterns in this run.\n"
                    f"- Do NOT carry forward prior auto-buckets for partition internals, EXT, INT_C2C, input ports, or PTECO; Python has already regenerated those for this run.\n"
                )

            if persona == 'po':
                triage_question = (
                    f"Triage all failing internal {args.mode} paths in partition '{partition}' "
                    f"(block '{block_label}', run '{run_label}').\n\n"
                    f"You are triaging as a PARTITION OWNER (PO) for partition '{partition}'.\n\n"
                    f"Here is the PO-scoped triage data (already computed — do NOT call triage_timing_run):\n"
                    f"{triage_json}\n\n"
                    f"IMPORTANT: The dataset is already restricted to internal failing paths whose startpoint and endpoint both resolve to partition '{partition}'.\n"
                    f"STO-owned C2C, EXT, input-port, and PTECO paths are excluded from this PO run and must not appear in your buckets.\n"
                    f"Python auto-buckets only the PO-scoped categories shown below:\n"
                    f"{waiver_prompt_line}"
                    f"  - {po_int_count} Partition_Internals ({len(po_int_buckets)} buckets)\n"
                    f"  - {input_port_count} INPUT PORTS ({len(input_port_buckets)} buckets)\n"
                    f"  - {int_c2c_count} INT_C2C ({len(int_c2c_buckets)} buckets)\n"
                    f"  - {ext_count} EXT ({len(ext_buckets)} buckets)\n"
                    f"  - {pteco_count} PTECO ({len(pteco_buckets)} buckets)\n"
                    f"Python will automatically merge any PO-scoped auto-buckets into the export.\n\n"
                    f"Your job: create buckets ONLY for the {remaining} remaining internal partition paths (if any).\n\n"
                    f"{existing_bucket_prompt}"
                    f"Workflow:\n"
                    f"1. Call review_auto_buckets({validate_params}, max_samples=3) to inspect a representative subset of the Python auto-buckets. If the auto-bucket count is large, do NOT try to review or annotate every auto-bucket in one pass. Add short, high-level LLM descriptions only to the reviewed subset with annotate_auto_buckets(...).\n"
                    f"2. If remaining paths exist, use query_timing_db on the temp view "
                    f"'{triage_data.get('remaining_c2c_ext', {}).get('remaining_view', 'triage_remaining_paths')}' "
                    f"to inspect the raw residual internal partition paths. The remaining_c2c_ext summaries are hints only.\n"
                    f"3. Classify: ECO (cell sizing), MOP (long net/high fanout), HRP (high logic depth).\n"
                    f"4. For each bucket: filters MUST include StartPin and/or EndPin regex.\n"
                    f"   Do NOT include PathType in filters — it is added automatically.\n"
                    f"   Do NOT create C2C, EXT, input-port, or PTECO buckets in PO mode.\n"
                    f"5. Call validate_buckets({validate_params}, buckets=<your remaining buckets only>).\n"
                    f"   Validation automatically includes Python auto-buckets.\n"
                    f"6. If validation reports unmatched paths, query the returned unmatched_view with query_timing_db, refine your buckets, and validate again. Do up to 3 total validation rounds before exporting.\n"
                    f"7. Only when coverage is acceptable, call export_bucket_file({export_params}, buckets=<your final remaining buckets only>).\n"
                    f"   If no remaining paths, pass buckets=[].\n"
                    f"8. Print summary: each bucket's category, path count, worst slack, plus final unmatched count."
                )
            else:
                auto_count = len(waiver_buckets) + len(po_int_buckets) + len(input_port_buckets) + len(int_c2c_buckets) + len(pteco_buckets) + len(ext_buckets)
                triage_question = (
                    f"Triage all failing {args.mode} paths in block '{block_label}', run '{run_label}'.\n\n"
                    f"You are triaging as a SECTION TIMING OWNER (STO).\n\n"
                    f"Here is the triage data (already computed — do NOT call triage_timing_run):\n"
                    f"{triage_json}\n\n"
                    f"IMPORTANT: Python has already auto-bucketed ALL paths:\n"
                    f"{waiver_prompt_line}"
                    f"  - {po_int_count} Partition_Internals ({len(po_int_buckets)} buckets)\n"
                    f"  - {input_port_count} INPUT PORTS ({len(input_port_buckets)} buckets)\n"
                    f"  - {int_c2c_count} INT_C2C ({len(int_c2c_buckets)} buckets)\n"
                    f"  - {ext_count} EXT paths ({len(ext_buckets)} buckets)\n"
                    f"  - {pteco_count} PTECO ({len(pteco_buckets)} buckets)\n"
                    f"Python will merge all {auto_count} auto-buckets into the export.\n\n"
                    f"Your job: create buckets ONLY for the {remaining} remaining paths (if any).\n"
                    f"These are the actual failing paths left after Python auto-bucket filters are applied.\n\n"
                    f"{existing_bucket_prompt}"
                    f"Workflow:\n"
                    f"1. Call review_auto_buckets({validate_params}, max_samples=3) to inspect a representative subset of the Python auto-buckets. If the auto-bucket count is large, do NOT try to review or annotate every auto-bucket in one pass. Add short, high-level LLM descriptions only to the reviewed subset with annotate_auto_buckets(...).\n"
                    f"2. If remaining paths exist, use query_timing_db on the temp view "
                    f"'{triage_data.get('remaining_c2c_ext', {}).get('remaining_view', 'triage_remaining_paths')}' "
                    f"to inspect the raw residual paths. The remaining_c2c_ext summaries are hints only.\n"
                    f"3. Classify: HRP (high logic depth), ECO (small slack), CON (constraints).\n"
                    f"4. For each bucket: filters MUST include StartPin and/or EndPin regex.\n"
                    f"   Do NOT include PathType in filters — it is added automatically.\n"
                    f"5. Call validate_buckets({validate_params}, buckets=<your remaining buckets only>).\n"
                    f"   Validation automatically includes Python's {auto_count} auto-buckets.\n"
                    f"6. If validation reports unmatched paths, query the returned unmatched_view with query_timing_db, refine your buckets, and validate again. Do up to 3 total validation rounds before exporting.\n"
                    f"7. Only when coverage is acceptable, call export_bucket_file({export_params}, buckets=<your final remaining buckets only>).\n"
                    f"   Python will prepend the {auto_count} auto-buckets.\n"
                    f"   If no remaining paths, pass buckets=[].\n"
                    f"8. Print triage summary: bucket #, classification, path count, worst slack, plus final unmatched count."
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
