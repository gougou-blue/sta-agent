"""
Block and run configuration for STA Agent.
Mirrors the dashboard's backend/config.js — same CSV paths.
"""

BLOCKS = {
    "d2d1": {
        "owner": "rnsajjan",
        "runs": [
            {
                "label": "26ww14.3_8thApril",
                "setup_csv": "/nfs/site/disks/nwp_fct_0004/rnsajjan/d2d1_0p5_26ww14.3_8thApril/runs/d2d1/1276.5_dot4/sta_pt/func.nom.TT_100.tttt/reports/d2d1.func.nom.TT_100.tttt.report_summary.max.csv.gz",
                "hold_csv": "/nfs/site/disks/nwp_fct_0004/rnsajjan/d2d1_0p5_26ww14.3_8thApril/runs/d2d1/1276.5_dot4/sta_pt/func4.high.TM_100.tttt/reports/d2d1.func4.high.TM_100.tttt.report_summary.min.csv.gz",
            },
            {
                "label": "26ww14.3",
                "setup_csv": "/nfs/site/disks/nwp_fct_0004/rnsajjan/d2d1_0p5_26ww14.3/runs/d2d1/1276.5_dot4/sta_pt/func.nom.TT_100.tttt/reports/d2d1.func.nom.TT_100.tttt.report_summary.max.csv.gz",
                "hold_csv": "/nfs/site/disks/nwp_fct_0004/rnsajjan/d2d1_0p5_26ww14.3/runs/d2d1/1276.5_dot4/sta_pt/func4.high.TM_100.tttt/reports/d2d1.func4.high.TM_100.tttt.report_summary.min.csv.gz",
            },
            {
                "label": "26ww13.5",
                "setup_csv": "/nfs/site/disks/nwp_fct_0004/rnsajjan/d2d1_0p5_26ww13.5/runs/d2d1/1276.5_dot4/sta_pt/func.nom.TT_100.tttt/reports/d2d1.func.nom.TT_100.tttt.report_summary.max.csv.gz",
                "hold_csv": "/nfs/site/disks/nwp_fct_0004/rnsajjan/d2d1_0p5_26ww13.5/runs/d2d1/1276.5_dot4/sta_pt/func4.high.TM_100.tttt/reports/d2d1.func4.high.TM_100.tttt.report_summary.min.csv.gz",
            },
        ],
    },
    "memstack": {
        "owner": "darylkow",
        "runs": [
            {
                "label": "default_stamping",
                "setup_csv": "/nfs/site/disks/nwp_fct_0004/darylkow/memstack_default_stamping/runs/memstack/1276.5_dot4/sta_pt/func.nom.TT_100.tttt/reports/memstack.func.nom.TT_100.tttt.report_summary.max.csv.gz",
                "hold_csv": "/nfs/site/disks/nwp_fct_0004/darylkow/memstack_default_stamping/runs/memstack/1276.5_dot4/sta_pt/func4.high.TM_100.tttt/reports/memstack.func4.high.TM_100.tttt.report_summary.min.csv.gz",
            },
            {
                "label": "26ww11.2",
                "setup_csv": "/nfs/site/disks/nwp_fct_0004/darylkow/memstack_0p5_26ww11.2/runs/memstack/1276.5_dot4/sta_pt/func.nom.TT_100.tttt/reports/memstack.func.nom.TT_100.tttt.report_summary.max.csv.gz",
                "hold_csv": "/nfs/site/disks/nwp_fct_0004/darylkow/memstack_0p5_26ww11.2/runs/memstack/1276.5_dot4/sta_pt/func4.high.TM_100.tttt/reports/memstack.func4.high.TM_100.tttt.report_summary.min.csv.gz",
            },
        ],
    },
    "uio_a_0": {
        "owner": "pavanmku",
        "runs": [
            {
                "label": "RTL13A_26ww15.1",
                "setup_csv": "/nfs/site/disks/nwp_fct_0004/pavanmku/0p5/uio_a_0/uio_a_0_0p5_RTL13A_26ww15.1/runs/uio_a_0/1276.5_dot4/sta_pt/func.nom.TT_100.tttt/reports/uio_a_0.func.nom.TT_100.tttt.report_summary.max.csv.gz",
                "hold_csv": "/nfs/site/disks/nwp_fct_0004/pavanmku/0p5/uio_a_0/uio_a_0_0p5_RTL13A_26ww15.1/runs/uio_a_0/1276.5_dot4/sta_pt/func4.high.TM_100.tttt/reports/uio_a_0.func4.high.TM_100.tttt.report_summary.min.csv.gz",
            },
            {
                "label": "26ww13.5",
                "setup_csv": "/nfs/site/disks/nwp_fct_0004/pavanmku/0p5/uio_a_0/uio_a_0_0p5_26ww13.5/runs/uio_a_0/1276.5_dot4/sta_pt/func.nom.TT_100.tttt/reports/uio_a_0.func.nom.TT_100.tttt.report_summary.max.csv.gz",
                "hold_csv": "/nfs/site/disks/nwp_fct_0004/pavanmku/0p5/uio_a_0/uio_a_0_0p5_26ww13.5/runs/uio_a_0/1276.5_dot4/sta_pt/func4.high.TM_100.tttt/reports/uio_a_0.func4.high.TM_100.tttt.report_summary.min.csv.gz",
            },
        ],
    },
    "d2d4": {
        "owner": "slbass",
        "runs": [
            {
                "label": "26ww15.2",
                "setup_csv": "/nfs/site/disks/nwp_fct_0004/slbass/d2d4_26ww15.2/runs/d2d4/1276.9/sta_pt/func.max_nom.TT_100.tttt/reports/d2d4.func.max_nom.TT_100.tttt.report_summary.max.csv.gz",
                "hold_csv": "/nfs/site/disks/nwp_fct_0004/slbass/d2d4_26ww15.2/runs/d2d4/1276.9/sta_pt/func.min_high.TM_100.tttt/reports/d2d4.func.min_high.TM_100.tttt.report_summary.min.csv.gz",
            },
            {
                "label": "26ww14.5",
                "setup_csv": "/nfs/site/disks/nwp_fct_0004/slbass/d2d4_26ww14.5/runs/d2d4/1276.9/sta_pt/func.max_nom.TT_100.tttt/reports/d2d4.func.max_nom.TT_100.tttt.report_summary.max.csv.gz",
                "hold_csv": "/nfs/site/disks/nwp_fct_0004/slbass/d2d4_26ww14.5/runs/d2d4/1276.9/sta_pt/func.min_high.TM_100.tttt/reports/d2d4.func.min_high.TM_100.tttt.report_summary.min.csv.gz",
            },
            {
                "label": "26ww14.4",
                "setup_csv": "/nfs/site/disks/nwp_fct_0004/slbass/d2d4_26ww14.4/runs/d2d4/1276.9/sta_pt/func.max_nom.TT_100.tttt/reports/d2d4.func.max_nom.TT_100.tttt.report_summary.max.csv.gz",
                "hold_csv": "/nfs/site/disks/nwp_fct_0004/slbass/d2d4_26ww14.4/runs/d2d4/1276.9/sta_pt/func.min_high.TM_100.tttt/reports/d2d4.func.min_high.TM_100.tttt.report_summary.min.csv.gz",
            },
        ],
    },
}

# DuckDB database path (on the Linux server)
DB_PATH = "/nfs/site/disks/nwp_fct_0001/jymarc/sta-agent/timing.duckdb"
