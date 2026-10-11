"""Make process-wide console output best-effort.

When the server is launched from a terminal/pipe that later goes away (the
launching shell is closed, a parent process exits, ...), every write to
stdout/stderr on Windows raises ``OSError: [WinError 233] No process is on
the other end of the pipe`` (EPIPE/EINVAL elsewhere). Diagnostic print()s
deep inside the stage runners then turn into stage failures. Wrapping the
standard streams so write/flush errors are swallowed keeps console logging
purely advisory.
"""

from __future__ import annotations

import sys


class _SafeStream:
    """Proxy a text stream, dropping output once the console is gone."""

    def __init__(self, stream):
        self._stream = stream
        self._broken = False

    def write(self, data):
        if self._broken:
            return len(data) if isinstance(data, str) else 0
        try:
            return self._stream.write(data)
        except (OSError, ValueError):
            self._broken = True
            return len(data) if isinstance(data, str) else 0

    def writelines(self, lines):
        for line in lines:
            self.write(line)

    def flush(self):
        if self._broken:
            return
        try:
            self._stream.flush()
        except (OSError, ValueError):
            self._broken = True

    def __getattr__(self, name):
        return getattr(self._stream, name)


def install_safe_console() -> None:
    """Wrap sys.stdout/sys.stderr once (idempotent; None streams left alone)."""
    for name in ("stdout", "stderr"):
        stream = getattr(sys, name, None)
        if stream is None or isinstance(stream, _SafeStream):
            continue
        setattr(sys, name, _SafeStream(stream))
