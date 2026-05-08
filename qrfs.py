#!/usr/bin/env python3
"""QRFS — documented entry point.

Run the QRFS Flask server directly::

    python qrfs.py [--debug] [--flask-dev] [--host=ADDR] [--port=N]

This file delegates to ``qrfs.__main__`` so that ``python qrfs.py``,
``python -m qrfs``, and the installed ``qrfs`` console script all behave
identically.
"""

from qrfs.__main__ import main

if __name__ == '__main__':
    main()
