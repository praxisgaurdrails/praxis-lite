"""
Frozen entry point for the Praxis Lite bundle.

PyInstaller freezes this into the ``praxis`` executable. It just hands
off to the Click CLI, which has all subcommands (install, enable,
disable, daemon, mcp, search, ...).
"""

import multiprocessing

from praxis.praxis_cli import main

if __name__ == "__main__":
    # Required so PyInstaller-frozen apps that spawn subprocesses work.
    multiprocessing.freeze_support()
    main()
