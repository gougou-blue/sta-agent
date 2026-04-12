#!/usr/bin/env python3
"""
Timing Analysis Agent — CLI interface.

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
        "description": "Execute a SQL query against the timing DuckDB database. Returns results as a list of rows. Use this to answer questions about timing paths, violations, and analysis.",
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
        "name": "list_available_data",
        "description": "List all blocks and runs available in the database with row counts.",
        "input_schema": {
            "type": "object",
            "properties": {},
        }
    },
    {
        "name": "list_reports",
        "description": "List available PrimeTime report files (.rpt.gz) for a specific block and run. Returns report names with file sizes. Use this to discover what reports exist before reading them.",
        "input_schema": {
            "type": "object",
            "properties": {
                "block": {
                    "type": "string",
                    "description": "Block name (e.g., d2d1, uio_a_0)"
                },
                "run_label": {
                    "type": "string",
                    "description": "Run label (e.g., 26ww14.3_8thApril)"
                },
                "mode": {
                    "type": "string",
                    "enum": ["setup", "hold"],
                    "description": "setup or hold — determines which scenario's reports to list"
                }
            },
            "required": ["block", "run_label", "mode"]
        }
    },
    {
        "name": "read_report",
        "description": "Read a PrimeTime report file (.rpt.gz). Can read first N lines, last N lines, or grep for a pattern. Use for detailed path analysis, timing loops, max transition, QoR, constraints, and other reports. Reports can be very large — always use max_lines or grep to limit output.",
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
                "report_name": {
                    "type": "string",
                    "description": "Report filename, e.g. 'timing_loops.rpt.gz', 'report_max_transition.rpt.gz', 'report_summary.max.rpt.gz'. Use list_reports to see available files."
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
                    "description": "Return only lines matching this pattern (case-insensitive regex). Useful to search for specific paths, clocks, or sections."
                },
                "context_lines": {
                    "type": "integer",
                    "description": "Number of lines of context around grep matches (default 2)."
                }
            },
            "required": ["block", "run_label", "mode", "report_name"]
        }
    },
]


def load_system_prompt():
    """Load the system prompt and append available data context."""
    with open(SYSTEM_PROMPT_PATH, "r") as f:
        prompt = f.read()

    # Append available blocks/runs
    context = "\n\n## Available Data\n"
    for block, data in BLOCKS.items():
        runs = ", ".join(r["label"] for r in data["runs"])
        context += f"- **{block}** (owner: {data['owner']}): {runs}\n"

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


def list_report_files(block, run_label, mode):
    """List .rpt.gz files in the reports directory."""
    reports_dir = get_reports_dir(block, run_label, mode)
    if not reports_dir:
        return {"error": f"No config found for {block}/{run_label}/{mode}"}
    if not os.path.isdir(reports_dir):
        return {"error": f"Directory not found: {reports_dir}"}

    files = []
    for f in sorted(os.listdir(reports_dir)):
        if f.endswith('.rpt.gz') or f.endswith('.rpt'):
            fpath = os.path.join(reports_dir, f)
            size = os.path.getsize(fpath)
            # Show human-readable size
            if size > 1024 * 1024:
                size_str = f"{size / (1024*1024):.1f}MB"
            elif size > 1024:
                size_str = f"{size / 1024:.1f}KB"
            else:
                size_str = f"{size}B"
            files.append({"name": f, "size": size_str})

    return {"directory": reports_dir, "files": files, "count": len(files)}


def read_report_file(block, run_label, mode, report_name, max_lines=200,
                     tail=False, grep=None, context_lines=2):
    """Read a .rpt.gz file with head/tail/grep support."""
    reports_dir = get_reports_dir(block, run_label, mode)
    if not reports_dir:
        return {"error": f"No config found for {block}/{run_label}/{mode}"}

    # Security: prevent path traversal
    if '..' in report_name or '/' in report_name:
        return {"error": "Invalid report name"}

    fpath = os.path.join(reports_dir, report_name)
    if not os.path.isfile(fpath):
        return {"error": f"File not found: {report_name}"}

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

    elif tool_name == "list_available_data":
        result = list_data(con)
        display_result(result)
        return json.dumps(result, default=str)

    elif tool_name == "list_reports":
        block = tool_input["block"]
        run_label = tool_input["run_label"]
        mode = tool_input["mode"]
        console.print(f"\n[dim]Listing reports for {block}/{run_label} ({mode})[/dim]\n")
        result = list_report_files(block, run_label, mode)
        if "error" not in result:
            for f in result["files"]:
                console.print(f"  [dim]{f['size']:>8s}  {f['name']}[/dim]")
            console.print(f"  [dim]({result['count']} report files)[/dim]")
        else:
            console.print(f"[red]{result['error']}[/red]")
        return json.dumps(result, default=str)

    elif tool_name == "read_report":
        block = tool_input["block"]
        run_label = tool_input["run_label"]
        mode = tool_input["mode"]
        report_name = tool_input["report_name"]
        max_lines = tool_input.get("max_lines", 200)
        tail = tool_input.get("tail", False)
        grep_pat = tool_input.get("grep")
        context_lines = tool_input.get("context_lines", 2)
        label = f"{block}/{run_label}/{report_name}"
        if grep_pat:
            console.print(f"\n[dim]Reading {label} (grep: {grep_pat})[/dim]\n")
        elif tail:
            console.print(f"\n[dim]Reading {label} (tail {max_lines})[/dim]\n")
        else:
            console.print(f"\n[dim]Reading {label} (head {max_lines})[/dim]\n")
        result = read_report_file(block, run_label, mode, report_name,
                                  max_lines, tail, grep_pat, context_lines)
        if "error" in result:
            console.print(f"[red]{result['error']}[/red]")
        else:
            console.print(f"[dim]({result['total_lines']} total lines)[/dim]")
        return json.dumps(result, default=str)

    return json.dumps({"error": f"Unknown tool: {tool_name}"})


def run_agent(con, client, question, block=None, run=None, mode=None, model=DIRECT_MODEL):
    """Run the agent loop: question → tool calls → analysis."""

    # Build the user message with optional context
    user_msg = question
    if block:
        user_msg += f"\n\nContext: block={block}"
    if run:
        user_msg += f", run={run}"
    if mode:
        user_msg += f", mode={mode}"

    system_prompt = load_system_prompt()
    messages = [{"role": "user", "content": user_msg}]

    console.print(f"\n[bold]Question:[/bold] {question}\n")

    # Agent loop — allow multiple tool calls
    for _ in range(10):  # safety limit
        response = client.messages.create(
            model=model,
            max_tokens=4096,
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
            break

        # If there were tool calls, add the assistant response and tool results
        if tool_results:
            messages.append({"role": "assistant", "content": response.content})
            messages.append({"role": "user", "content": tool_results})
        else:
            break

    console.print()


def interactive_mode(con, client, model=DIRECT_MODEL):
    """Interactive REPL mode."""
    console.print("[bold]Timing Analysis Agent[/bold] — Interactive Mode")
    console.print("Type your question, or 'quit' to exit.\n")

    while True:
        try:
            question = console.input("[bold green]> [/bold green]").strip()
        except (EOFError, KeyboardInterrupt):
            break

        if not question or question.lower() in ("quit", "exit", "q"):
            break

        run_agent(con, client, question, model=model)


def main():
    parser = argparse.ArgumentParser(description="Timing Analysis Agent")
    parser.add_argument("question", nargs="?", help="Question to ask (or use --interactive)")
    parser.add_argument("--interactive", "-i", action="store_true", help="Interactive mode")
    parser.add_argument("--block", "-b", help="Focus on a specific block")
    parser.add_argument("--run", "-r", help="Focus on a specific run")
    parser.add_argument("--mode", "-m", choices=["setup", "hold"], help="Focus on setup or hold")
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

    # Connect to DuckDB
    if not os.path.exists(args.db):
        console.print(f"[red]Error: Database not found at {args.db}[/red]")
        console.print("Run `python ingest.py` first to build the database.")
        sys.exit(1)

    con = duckdb.connect(args.db, read_only=True)

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
        if args.interactive:
            interactive_mode(con, client, model)
        elif args.question:
            run_agent(con, client, args.question, args.block, args.run, args.mode, model=model)
        else:
            parser.print_help()
    finally:
        con.close()


if __name__ == "__main__":
    main()
