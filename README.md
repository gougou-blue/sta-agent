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

# Enable milestone-specific waiver buckets
python3 agent.py --triage --reports-dir /path/to/sta_pt/.../reports/ -m setup --milestone 0p5
python3 agent.py --triage --reports-dir /path/to/sta_pt/.../reports/ -m hold --milestone 0p8

# PO mode — drills into a specific partition's internal paths
python3 agent.py --triage --persona po -p pard2d1uladda1 -b d2d1 -r 26ww14.3 -m setup
python3 agent.py --triage --persona po -p pard2d1uladda1 --reports-dir /path/to/sta_pt/.../reports/ -m setup

# Specify output path
python3 agent.py --triage -b d2d1 -r 26ww14.3 -m setup -o /nfs/.../d2d1_setup.bucket

# Update an existing STO bucket file for a new run
python3 agent.py --triage --reports-dir /path/to/sta_pt/.../reports/ -m setup --existing-bucket ./buckets/d2d1_setup.bucket -o ./buckets/d2d1_setup_updated.bucket
```

**Persona modes:**
| Flag | Role | Focus |
|------|------|-------|
| `--persona sto` (default) | Section Timing Owner | C2C and EXT paths; partition internals lumped as PO_INT |
| `--persona po -p <partition>` | Partition Owner | Internal paths within the selected partition only; detailed sub-buckets by logic cone, severity, FC recipe |

PO mode scopes triage to failing paths whose startpoint and endpoint both resolve to the selected partition. It excludes STO-owned C2C, EXT, input-port, and PTECO paths from the PO bucket file.
When you use `--reports-dir` in PO mode, the agent requires a partition-specific summary CSV like `pard2d4uladda1.func.max_nom.TT_100.tttt.report_summary.max.csv.gz`. If that partition report is missing, PO triage fails with a report-not-found error.

The agent will:
1. Analyze all failing paths grouped by clock domain, partition, path type, and severity
2. Classify using the IRIS waterfall: Constraints → Feedthrough → Optimization → Additional
3. Validate bucket coverage — iterate on the unmatched residual paths until unmatched is under 5% of total failing paths
4. Generate a `.bucket` file you can load directly in Timing Lite:
   ```bash
   timinglite.py --bucket ./buckets/d2d1_26ww14.3_setup.bucket <report>
   ```

If you pass `--existing-bucket`, the agent parses the active bucket lines from that file and uses them as the starting STO bucket set for the new run. It keeps buckets that still match, fixes or drops stale ones, and adds new residual buckets as needed. Python still regenerates the auto-buckets for partition internals, EXT, INT_C2C, input ports, and PTECO for the current run.

If you pass `--milestone`, Python can also auto-create a milestone waiver bucket before LLM triage:
- `0p5` setup uses `PercentPeriod:>-20`; `0p5` hold uses `Slack:>-100`
- `0p8` setup uses `PercentPeriod:>-5`; `0p8` hold uses `Slack:>-30`
- `1p0` disables waiver buckets

## Recommended team model

Do not force one shared prompt/config for every block in the team. Different designs have different hierarchy depth, partition naming, IO conventions, and recurring failure patterns. The better model is:

- Keep one shared codebase for the CLI and triage workflow.
- Treat `--reports-dir` as the default team workflow. Ingest is optional and not required for normal design adoption.
- Let each design owner keep a design-specific branch or clone with its own prompt tuning and, only if needed, design-specific config.
- Only merge changes back to shared `main` when they are clearly generic and help multiple designs.

## Create your own design-specific version

### Path 1: zero-code adoption

If a team member only wants to analyze one run or a small number of runs, they do not need to edit the repo at all.

```bash
python3 agent.py --reports-dir /path/to/my_design/.../reports/ "analyze worst setup paths"
python3 agent.py --reports-dir /path/to/my_design/.../reports/ -i
python3 agent.py --triage --reports-dir /path/to/my_design/.../reports/ -m setup
```

Use this path when:

- The design is new and you are still learning what makes it different.
- You do not need run-to-run comparisons or historical trends.
- You want to test whether the prompt understands your report content before customizing anything.

### Path 2: design-specific agent variant

Use this when a design has stable naming conventions and repeated triage needs.

Important: a design-specific branch does not have to mean hard-coding the block into the shared agent. For many teams, the branch is mainly for prompt tuning and local examples while day-to-day analysis still uses `--reports-dir`.

1. Clone the repo and create a branch for the design.

```bash
git clone https://github.com/gougou-blue/sta-agent.git
cd sta-agent
git checkout -b my_design_agent
```

2. Only add the design to `config.py` if you want named runs, persistent shortcuts, or pre-defined hierarchy controls for that design.

```python
"my_design": {
   "owner": "myintelid",
   "leaf_depth": 1,
   "leaf_partitions_n1": [],
   "runs": [
      {
         "label": "26ww16.1",
         "setup_csv": "/nfs/.../my_design.report_summary.max.csv.gz",
         "hold_csv": "/nfs/.../my_design.report_summary.min.csv.gz",
      },
   ],
},
```

3. Set the hierarchy controls for the design.

- Leave `leaf_depth` at `1` if the real partitions live at the top child level.
- Set `leaf_depth` to `2` if the real partitions are one level deeper.
- Use `leaf_partitions_n1` for exceptions like `pardfi` where some real partitions stay at the higher level.

4. Ingest is optional. Most teams can skip it unless they want trends, regression comparisons, or persistent historical queries.

```bash
python3 ingest.py --block my_design
```

5. Tune `prompts/system.txt` for design-specific language.

Good prompt edits are usually small and concrete:

- Common partition names or wrapper conventions.
- Special port naming patterns.
- Known path groups used by the design.
- Recurring false-path or constraint-review patterns.
- Design-specific ownership rules for STO vs PO triage.

6. Test with normal Q&A first, then triage.

```bash
python3 agent.py "worst 20 setup paths in my_design 26ww16.1"
python3 agent.py --triage -b my_design -r 26ww16.1 -m setup
```

7. Keep the variant local to the design team unless the tuning is clearly generic.

## What each team should customize

### Required for a serious design-specific variant

- Nothing, if the team is using `--reports-dir` only.

### Usually useful

- `prompts/system.txt`: design vocabulary, hierarchy wording, and triage hints.
- `README.md`: local usage examples for that design team.

### Needed only when the design wants stable built-in defaults

- `config.py`: block name, owner, run labels, CSV paths, hierarchy depth.
- `prompts/system.txt`: design vocabulary and triage hints.

### Usually not needed at first

- `agent.py`: only change code when the design exposes a real structural difference in the data model or bucket logic.

## Branch policy

- `config.py` is not the only thing a design branch may change. The most common design-local changes are `prompts/system.txt`, `README.md`, and sometimes `config.py`.
- Design-specific engineers can commit to their own branch. Committing to a private branch or design-local branch is explicitly OK.
- What should not happen is merging design-specific prompt/config/README changes into shared `main` unless they are clearly generic.
- If the team shares one remote, use personal or design-named branches. If the team wants stronger isolation, use a fork.
- The safe rule is: private branch commit is OK, merge to shared `main` is not OK unless the change is a common engine improvement.

## Suggested rollout for a team

1. Pick one design owner and one active run.
2. Start with `--reports-dir` and collect a few successful queries.
3. If the agent is useful, create a design branch and tune `prompts/system.txt` for the naming patterns that matter in that design.
4. Add `config.py` entries only if the design wants stable named runs or built-in hierarchy defaults.
5. Only merge code changes back to the shared repo if they are generic across multiple designs.

## Rule of thumb

Share the engine. Do not share one frozen design personality.

The CLI and validation loop can be common. The design-specific pieces should stay close to the engineers who know that block's hierarchy and failure modes.

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

Raw ad-hoc `query_csv` access sees PSGen's original CSV headers. The pre-ingested DuckDB `paths` table uses normalized names like `startpoint`, `endpoint`, `launch_clock`, and `capture_clock`, but direct CSV queries often need PSGen names such as `start_pin`, `end_pin`, `start_clock`, `end_clock`, and `path_delay_type` unless you alias them in SQL.

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
