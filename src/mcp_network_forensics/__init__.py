"""MCP Network Forensics Server."""

__version__ = "0.1.0"
__author__ = "MCP Network Forensics Team"

from .capture.file_capture import FileCaptureManager

__all__ = [
    "FileCaptureManager",
]
