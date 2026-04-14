#!/usr/bin/env python3
"""Quick script to inspect child_int_type values in memstack CSV."""
import duckdb

csv = "/nfs/site/disks/nwp_fct_0004/darylkow/memstack_default_stamping/runs/memstack/1276.5_dot4/sta_pt/func.nom.TT_100.tttt/reports/memstack.func.nom.TT_100.tttt.report_summary.max.csv.gz"

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
