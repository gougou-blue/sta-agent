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

## What it can do

- **Path analysis**: Worst paths, root cause identification, fix recommendations
- **Run comparison**: What regressed, what improved between runs
- **Report reading**: Timing loops, max transition, QoR, constraints, untested paths
- **Trend analysis**: Violations across work weeks (with pre-ingested data)
- **Ad-hoc queries**: SQL against any CSV.gz on NFS via DuckDB

## Architecture

```
agent.py            — CLI: question → Claude → SQL/reports → analysis
config.py           — Block/run configuration (for pre-ingested data)
ingest.py           — Parse sta_pt CSV.gz → DuckDB (optional)
prompts/system.txt  — STA domain knowledge and analysis guidelines
```

## Token refresh

GNAI tokens expire periodically. Visit https://gnai.intel.com/auth/oauth2/sso to get a fresh one.

## Feedback

Report issues or suggestions to jymarc@intel.com
