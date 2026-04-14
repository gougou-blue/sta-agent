#!/usr/bin/env python3
"""Quick script to inspect child_int_type values in a timing CSV."""
import duckdb, sys, os

candidates = [
    "/nfs/site/disks/nwp_fct_0004/darylkow/memstack_default_stamping/runs/memstack/1276.5_dot4/sta_pt/func.nom.TT_100.tttt/reports/memstack.func.nom.TT_100.tttt.report_summary.max.csv.gz",
    "/nfs/site/disks/nwp_fct_0004/darylkow/memstack_0p5_26ww11.2/runs/memstack/1276.5_dot4/sta_pt/func.nom.TT_100.tttt/reports/memstack.func.nom.TT_100.tttt.report_summary.max.csv.gz",
]

# Allow passing CSV path as argument
if len(sys.argv) > 1:
    csv = sys.argv[1]
else:
    csv = None
    for c in candidates:
        if os.path.exists(c):
            csv = c
            break
    if not csv:
        print("No CSV found. Pass path as argument: python3 check_child_int_type.py <csv_path>")
        sys.exit(1)

print(f"Using: {csv}\n")
con = duckdb.connect()

def query(sql):
    result = con.execute(sql)
    cols = [d[0] for d in result.description]
    rows = result.fetchall()
    # Print as table
    widths = [max(len(str(c)), max((len(str(r[i])) for r in rows), default=0)) for i, c in enumerate(cols)]
    header = " | ".join(str(c).ljust(w) for c, w in zip(cols, widths))
    print(header)
    print("-+-".join("-" * w for w in widths))
    for r in rows:
        print(" | ".join(str(v).ljust(w) for v, w in zip(r, widths)))
    print(f"({len(rows)} rows)\n")

print("=== child_int_type x int_ext x int_ext_child (failing paths) ===")
query(f"""
    SELECT child_int_type, int_ext, int_ext_child, COUNT(*) as cnt
    FROM read_csv_auto('{csv}')
    WHERE normal_slack < 0
    GROUP BY child_int_type, int_ext, int_ext_child
    ORDER BY cnt DESC
""")

print("=== thru_children breakdown for INT paths ===")
query(f"""
    SELECT thru_children, child_int_type, COUNT(*) as cnt
    FROM read_csv_auto('{csv}')
    WHERE normal_slack < 0 AND int_ext = 'INT'
    GROUP BY thru_children, child_int_type
    ORDER BY cnt DESC
""")

print("=== EXT paths: n-1 partition crossing + clock domain (top 20) ===")
query(f"""
    SELECT
        split_part(start_pin, '/', 1) as sp_n1,
        split_part(end_pin, '/', 1) as ep_n1,
        start_clock, end_clock,
        COUNT(*) as cnt,
        ROUND(MIN(normal_slack), 1) as worst_slack
    FROM read_csv_auto('{csv}')
    WHERE normal_slack < 0 AND int_ext = 'EXT'
    GROUP BY sp_n1, ep_n1, start_clock, end_clock
    ORDER BY cnt DESC
    LIMIT 20
""")

print("=== EXT sample startpoints (first 10) ===")
query(f"""
    SELECT start_pin, end_pin, int_ext, normal_slack
    FROM read_csv_auto('{csv}')
    WHERE normal_slack < 0 AND int_ext = 'EXT'
    ORDER BY normal_slack ASC
    LIMIT 10
""")
