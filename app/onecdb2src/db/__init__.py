"""Direct, read-only database capture; connection options are never receipts."""
from .capture import capture, CaptureError

__all__ = ['capture', 'CaptureError']
