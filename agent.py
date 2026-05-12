#!/usr/bin/env python3
"""Compatibility wrapper for PathMind.

PathMind is the primary CLI. This file keeps existing `python agent.py ...`
commands working during the transition.
"""

from pathmind import main


if __name__ == "__main__":
    main()
