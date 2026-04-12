#!/usr/bin/env python3
"""
Ingest sta_pt CSV.gz files into a DuckDB database for the timing analysis agent.

Usage:
    python ingest.py                  # Ingest all blocks/runs from config
    python ingest.py --block d2d1     # Ingest only a specific block
    python ingest.py --fresh          # Drop and recreate the table
"""

import argparse
import csv
import gzip
import os
import sys
import time

import duckdb

from config import BLOCKS, DB_PATH


CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS paths (
    block       VARCHAR NOT NULL,
    run_label   VARCHAR NOT NULL,
    mode        VARCHAR NOT NULL,   -- 'setup' or 'hold'
    -- Core timing fields
    slack                DOUBLE,
    clock_percentage     DOUBLE,
    period               DOUBLE,
    -- Path identification
    startpoint           VARCHAR,
    endpoint             VARCHAR,
    launch_clock         VARCHAR,
    capture_clock        VARCHAR,
    path_group           VARCHAR,
    -- Classification
    int_ext              VARCHAR,    -- INT or EXT
    int_ext_child        VARCHAR,    -- R2R, C2C, etc.
    driver_partition     VARCHAR,
    receiver_partition   VARCHAR,
    -- Path characteristics
    levels_of_logic      INTEGER,
    num_unique_fanout    INTEGER,
    path_type            VARCHAR,    -- max or min
    -- Raw row for anything else needed
    raw_row              VARCHAR,
    -- Ingest metadata
    ingested_at          TIMESTAMP DEFAULT current_timestamp
);
"""

CREATE_INDEX_SQL = [
    "CREATE INDEX IF NOT EXISTS idx_paths_block_run ON paths (block, run_label, mode);",
    "CREATE INDEX IF NOT EXISTS idx_paths_slack ON paths (slack);",
    "CREATE INDEX IF NOT EXISTS idx_paths_pct ON paths (clock_percentage);",
    "CREATE INDEX IF NOT EXISTS idx_paths_int_ext ON paths (int_ext);",
]


def safe_float(val):
    """Parse a float, returning None for empty/invalid values."""
    if not val or val.strip() in ('', '.', 'N/A', 'NA', 'nan'):
        return None
    try:
        return float(val.strip().replace('%', ''))
    except ValueError:
        return None


def safe_int(val):
    """Parse an int, returning None for empty/invalid values."""
    if not val or val.strip() in ('', '.', 'N/A', 'NA', 'nan'):
        return None
    try:
        return int(float(val.strip()))
    except ValueError:
        return None


def ingest_csv(con, block, run_label, csv_path, mode):
    """Read a single CSV.gz and insert failing paths into DuckDB."""
    if not csv_path or not os.path.exists(csv_path):
        print(f"  SKIP {mode}: file not found — {csv_path}")
        return 0

    # Check if already ingested
    count = con.execute(
        "SELECT COUNT(*) FROM paths WHERE block=? AND run_label=? AND mode=?",
        [block, run_label, mode]
    ).fetchone()[0]
    if count > 0:
        print(f"  SKIP {mode}: already ingested ({count:,} rows)")
        return count

    print(f"  Ingesting {mode}: {csv_path}")
    start = time.time()
    total_rows = 0
    batch = []
    BATCH_SIZE = 10000

    INSERT_SQL = """INSERT INTO paths (
        block, run_label, mode, slack, clock_percentage, period,
        startpoint, endpoint, launch_clock, capture_clock, path_group,
        int_ext, int_ext_child, driver_partition, receiver_partition,
        levels_of_logic, num_unique_fanout, path_type, raw_row
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"""

    try:
        with gzip.open(csv_path, 'rt', errors='replace') as f:
            reader = csv.DictReader(f)
            for row in reader:
                slack = safe_float(row.get('slack', ''))
                pct = safe_float(row.get('clock_percentage', ''))

                # Only keep failing paths (negative slack)
                if slack is None or slack >= 0:
                    continue

                int_ext = (row.get('int_ext', '') or '').strip().upper()
                int_ext_child = (row.get('int_ext_child', '') or '').strip().upper()

                batch.append((
                    block,
                    run_label,
                    mode,
                    slack,
                    pct,
                    safe_float(row.get('period', '')),
                    row.get('startpoint', '').strip(),
                    row.get('endpoint', '').strip(),
                    row.get('launch_clock', '').strip(),
                    row.get('capture_clock', '').strip(),
                    row.get('path_group', '').strip(),
                    int_ext,
                    int_ext_child,
                    row.get('driver_partition', '').strip(),
                    row.get('receiver_partition', '').strip(),
                    safe_int(row.get('levels_of_logic', '')),
                    safe_int(row.get('num_unique_fanout', '')),
                    row.get('path_type', '').strip(),
                    '',  # raw_row — skip to save space
                ))

                if len(batch) >= BATCH_SIZE:
                    con.executemany(INSERT_SQL, batch)
                    total_rows += len(batch)
                    batch = []

    except (gzip.BadGzipFile, EOFError) as e:
        print(f"  WARNING: gzip error (partial read): {e}")

    if batch:
        con.executemany(INSERT_SQL, batch)
        total_rows += len(batch)

    # Flush to disk to free memory
    con.execute("CHECKPOINT")

    elapsed = time.time() - start
    print(f"  Done ({total_rows:,} failing paths, {elapsed:.1f}s)")
    return total_rows


def main():
    parser = argparse.ArgumentParser(description="Ingest sta_pt CSV files into DuckDB")
    parser.add_argument("--block", help="Ingest only this block")
    parser.add_argument("--fresh", action="store_true", help="Drop and recreate the paths table")
    parser.add_argument("--db", default=DB_PATH, help=f"DuckDB path (default: {DB_PATH})")
    args = parser.parse_args()

    # Ensure DB directory exists
    db_dir = os.path.dirname(args.db)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)

    con = duckdb.connect(args.db)
    con.execute("SET memory_limit='2GB'")

    if args.fresh:
        print("Dropping existing paths table...")
        con.execute("DROP TABLE IF EXISTS paths")

    con.execute(CREATE_TABLE_SQL)
    for sql in CREATE_INDEX_SQL:
        con.execute(sql)

    blocks_to_ingest = {args.block: BLOCKS[args.block]} if args.block else BLOCKS
    total = 0

    for block_name, block_data in blocks_to_ingest.items():
        print(f"\n[{block_name}] (owner: {block_data['owner']})")
        for run in block_data["runs"]:
            label = run["label"]
            print(f"  Run: {label}")
            total += ingest_csv(con, block_name, label, run.get("setup_csv"), "setup")
            total += ingest_csv(con, block_name, label, run.get("hold_csv"), "hold")

    con.close()
    print(f"\nDone. Total failing paths in DB: {total:,}")
    print(f"Database: {args.db}")


if __name__ == "__main__":
    main()
