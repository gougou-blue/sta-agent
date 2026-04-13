# STA Agent

AI-powered CLI for Static Timing Analysis. Ask questions about your PrimeTime reports in plain English — get analysis, root causes, and fix recommendations.

## Setup (5 minutes)

```bash
# 1. Clone
git clone https://github.com/gougou-blue/sta-agent.git
cd sta-agent

# 2. Install dependencies (Python 3.11+)
python3 -m pip install --user -r requirements.txt

# 3. Get your GNAI token
#    - Request AGS entitlement: https://goto.intel.com/ags-gnai-public
#    - Generate token: https://gnai.intel.com/auth/oauth2/sso
#    (csh)
setenv GNAI_API_KEY "your-token-here"
#    (bash)
export GNAI_API_KEY="your-token-here"
```

## Usage

### Analyze any timing run (no setup, no ingest)

Point `--reports-dir` at your sta_pt reports directory:

```bash
python3 agent.py --reports-dir /path/to/sta_pt/.../reports/ "analyze worst setup paths and suggest fixes"
python3 agent.py --reports-dir /path/to/sta_pt/.../reports/ "check for timing loops"
python3 agent.py --reports-dir /path/to/sta_pt/.../reports/ "any max transition violations?"
```

### Interactive mode (follow-up questions)

```bash
python3 agent.py -i --reports-dir /path/to/reports/
> worst 10 setup paths?
[... analysis ...]
> does the PHY from our previous project have the same issue?
[... follow-up with context ...]
> what about hold violations?
> reset    # clear history and start fresh
> quit
```

### Pre-ingested data (NWPNIO blocks)

For blocks already in the database:

```bash
python3 agent.py "worst 20 setup paths in d2d4 26ww15.2"
python3 agent.py "compare d2d4 ww15.2 vs ww14.5 setup — what regressed?"
python3 agent.py "which clock domains have the most hold violations?"
python3 agent.py -i   # interactive with pre-ingested data
```

### Triage a timing run

Auto-bucket failing paths and generate a timinglite-compatible bucket file:

```bash
# STO mode (default) — focuses on C2C/EXT paths, lumps partition internals
python3 agent.py --triage -b d2d1 -r 26ww14.3 -m setup
python3 agent.py --triage --reports-dir /path/to/sta_pt/.../reports/ -m setup

# PO mode — drills into a specific partition's internal paths
python3 agent.py --triage --persona po -p pard2d1uladda1 -b d2d1 -r 26ww14.3 -m setup

# Specify output path
python3 agent.py --triage -b d2d1 -r 26ww14.3 -m setup -o /nfs/.../d2d1_setup.bucket
```

**Persona modes:**
| Flag | Role | Focus |
|------|------|-------|
| `--persona sto` (default) | Section Timing Owner | C2C and EXT paths; partition internals lumped as PO_INT |
| `--persona po -p <partition>` | Partition Owner | Internal paths within the partition; detailed sub-buckets by logic cone, severity, FC recipe |

The agent will:
1. Analyze all failing paths grouped by clock domain, partition, path type, and severity
2. Classify using the IRIS waterfall: Constraints → Feedthrough → Optimization → Additional
3. Validate bucket coverage — iterate until the catch-all (MSC-003) is under 5% of total failing paths
4. Generate a `.bucket` file you can load directly in Timing Lite:
   ```bash
   timinglite.py --bucket ./buckets/d2d1_26ww14.3_setup.bucket <report>
   ```

## What it can do

- **Path analysis**: Worst paths, root cause identification, fix recommendations
- **Run comparison**: What regressed, what improved between runs
- **Report reading**: Timing loops, max transition, QoR, constraints, untested paths
- **Trend analysis**: Violations across work weeks (with pre-ingested data)
- **Ad-hoc queries**: SQL against any CSV.gz on NFS via DuckDB
- **Triage & bucketing**: Auto-group failing paths into actionable buckets, generate timinglite bucket files

## Architecture

```
agent.py            — CLI: question → Claude → SQL/reports → analysis
config.py           — Block/run configuration (for pre-ingested data)
ingest.py           — Parse sta_pt CSV.gz → DuckDB (optional)
prompts/system.txt  — STA domain knowledge and analysis guidelines
```

## Token refresh

GNAI tokens expire periodically. Visit https://gnai.intel.com/auth/oauth2/sso to get a fresh one.

## VS Code Integration

### Option 1: VS Code Tasks (quick start)

Run the agent directly from VS Code without leaving the editor:

1. Open the sta-agent folder in VS Code
2. Press `Ctrl+Shift+P` → **Tasks: Run Task**
3. Pick one:
   - **STA Agent: Ask Question** — prompts for a one-shot question
   - **STA Agent: Interactive Mode** — starts the interactive REPL in the terminal
   - **STA Agent: Analyze Reports Dir** — prompts for an NFS reports path, then starts interactive mode

Make sure `GNAI_API_KEY` is set in your shell/environment before launching VS Code.

### Option 2: MCP Server (Copilot Chat integration)

Ask STA questions directly in GitHub Copilot Chat — no terminal needed:

1. Install the MCP dependency:
   ```bash
   pip install mcp
   ```

2. The `.vscode/mcp.json` is already configured. VS Code will auto-detect it.

3. In Copilot Chat, the STA tools become available automatically. Ask questions like:
   - *"List the available timing data in the database"*
   - *"Query the worst 10 setup paths in d2d1"*
   - *"Read the timing loop report for d2d4 26ww15.2"*

   Copilot will call `query_timing_db`, `list_reports`, `read_report`, etc. on your behalf.

**Available MCP tools:**
| Tool | Description |
|------|-------------|
| `query_timing_db` | SQL against the pre-ingested DuckDB paths table |
| `query_csv` | SQL against any CSV.gz on NFS via `read_csv_auto()` |
| `list_available_data` | Show all blocks/runs in the database |
| `list_reports` | List .rpt.gz/.csv.gz files in a reports directory |
| `read_report` | Read a PrimeTime report with head/tail/grep |
| `triage_timing_run` | Analyze failing paths and group into bucket candidates |
| `export_bucket_file` | Generate a timinglite-compatible bucket file |

## Feedback

Report issues or suggestions to jean.marc@intel.com
