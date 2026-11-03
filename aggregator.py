"""Entry point kept for compatibility: ``python aggregator.py [options]``."""

import sys

from threatkill.pipeline import main

if __name__ == "__main__":
    sys.exit(main())
