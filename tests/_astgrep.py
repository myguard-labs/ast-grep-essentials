"""Shared helper for resolving the ast-grep binary across test modules.

Provides a single resolver that checks:
1. The local node_modules/.bin/ast-grep if it exists and is executable
2. The system PATH via shutil.which("ast-grep")
3. Returns None if neither is found

Test modules import this helper and skip with an actionable message
when the binary is unavailable.
"""

import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def resolve_ast_grep():
    """Resolve the ast-grep binary.

    Returns:
        Path to ast-grep if found, None if unavailable.
    """
    # Try local node_modules first
    local_binary = ROOT / "node_modules" / ".bin" / "ast-grep"
    if local_binary.exists() and local_binary.is_file() and (local_binary.stat().st_mode & 0o111):
        return local_binary

    # Try system PATH
    system_binary = shutil.which("ast-grep")
    if system_binary:
        return Path(system_binary)

    return None
