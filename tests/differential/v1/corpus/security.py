import tempfile

_unsafe_path = tempfile.mktemp()  # nosec B306
with tempfile.NamedTemporaryFile() as _safe_file:
    pass
