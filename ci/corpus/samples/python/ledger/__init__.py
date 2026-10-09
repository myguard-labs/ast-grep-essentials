"""Small ledger service used as fixed scan corpus.

The package is never imported or executed; it exists so a rule change shows up
either as new noise on the safe majority of this code or as lost recall on the
handful of deliberate findings.
"""

__all__ = ["api", "auth", "config", "storage", "tasks"]
