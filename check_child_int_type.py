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

print("=== child_int_type x int_ext x int_ext_child (failing paths) ===")
con.execute(f"""
    SELECT child_int_type, int_ext, int_ext_child, COUNT(*) as cnt
    FROM read_csv_auto('{csv}')
    WHERE normal_slack < 0
    GROUP BY child_int_type, int_ext, int_ext_child
    ORDER BY cnt DESC
""").show()

print()
print("=== thru_children breakdown for INT paths ===")
con.execute(f"""
    SELECT thru_children, child_int_type, COUNT(*) as cnt
    FROM read_csv_auto('{csv}')
    WHERE normal_slack < 0 AND int_ext = 'INT'
    GROUP BY thru_children, child_int_type
    ORDER BY cnt DESC
""").show()
