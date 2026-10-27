#!/usr/bin/env python3
"""A local fixture executable used in place of nxc for subprocess integration."""

import os
from pathlib import Path
import sys


sys.stdout.write(Path(os.environ["NXC_FIXTURE_PATH"]).read_text())
sys.stderr.write("fixture stderr")
sys.exit(int(os.environ.get("NXC_FIXTURE_EXIT_CODE", "0")))
