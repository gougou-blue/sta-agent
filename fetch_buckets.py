#!/usr/bin/env python3
"""Fetch real IRIS bucket files for learning timinglite format."""
import sys

files = [
    "/nfs/site/disks/nwp_fct_0003/iris_timing_lite/nioa0/d2d1/bucket_filters/d2d1.func.nom.TT_100.tttt.iris.all",
    "/nfs/site/disks/nwp_fct_0003/iris_timing_lite/nioa0/memstack/links/26ww14.4/iris_buckets.func.nom.TT_100.tttt.cfg",
    "/nfs/site/disks/nwp_fct_0003/iris_timing_lite/nioa0/uio_a_0/links/26ww15.2/iris_buckets.func.nom.TT_100.tttt.cfg",
]

for f in files:
    print(f"{'='*80}")
    print(f"FILE: {f}")
    print(f"{'='*80}")
    try:
        with open(f) as fh:
            print(fh.read())
    except Exception as e:
        print(f"ERROR: {e}")
    print()
