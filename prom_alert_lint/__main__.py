"""Module runner for python -m prom_alert_lint."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
