# SPDX-License-Identifier: MIT
"""Library behind tools/cycle.py: one generic boot cycle instead of per-generation scripts.

Modules: common (workspace, hashing, host checks), evidence (what the stopped-state
collectors already captured), observers (the pinned collector programs rendered for
one run), capture, preserve, retire, launch, storage and status.
"""
