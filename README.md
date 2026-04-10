# Timing Analysis Agent

AI-powered CLI tool for analyzing STA (Static Timing Analysis) timing violations from PrimeTime sta_pt reports.

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Set API key
export ANTHROPIC_API_KEY=your-key-here

# 3. Ingest CSV data into DuckDB
python ingest.py

# 4. Ask questions
python agent.py "top 10 worst setup paths in d2d1 latest run"
python agent.py -i   # interactive mode
```

## Commands

### Ingest
```bash
python ingest.py                  # Ingest all blocks/runs
python ingest.py --block d2d1     # Ingest one block
python ingest.py --fresh          # Drop and rebuild
```

### Query
```bash
# One-shot questions
python agent.py "worst 20 setup paths in d2d4 26ww15.2"
python agent.py "compare d2d4 ww15.2 vs ww14.5 setup — what regressed?"
python agent.py "which clock domains have the most hold violations in memstack?"
python agent.py "top 10 worst paths in d2d1 and propose fixes"

# With filters
python agent.py --block d2d1 --mode setup "worst external paths and suggest actions"

# Interactive mode
python agent.py --interactive
```

## Architecture

```
config.py           — Block/run/CSV path configuration
ingest.py           — Parse sta_pt CSV.gz → DuckDB
agent.py            — CLI: question → Claude → SQL → analysis
prompts/system.txt  — Domain knowledge and analysis guidelines
```

## Data Flow

1. **ingest.py** reads sta_pt `report_summary.{max|min}.csv.gz` files
2. Extracts all failing paths (negative slack) with full metadata
3. Stores in DuckDB (`paths` table) with indexes on slack, block, int_ext
4. **agent.py** sends user question + schema + domain context to Claude
5. Claude generates SQL, agent executes on DuckDB, Claude analyzes results
