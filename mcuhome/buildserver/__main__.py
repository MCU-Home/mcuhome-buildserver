# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""``python -m mcuhome.buildserver``."""

from __future__ import annotations

import sys

from mcuhome.buildserver.server import main

if __name__ == "__main__":
    sys.exit(main())
