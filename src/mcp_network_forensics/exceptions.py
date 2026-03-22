"""Custom exceptions for MCP Network Forensics."""


class MCPNetworkForensicsError(Exception):
    """Base exception for MCP Network Forensics."""
    pass


class ValidationError(MCPNetworkForensicsError):
    """Raised when input validation fails."""
    pass


class SecurityError(MCPNetworkForensicsError):
    """Raised when security check fails."""
    pass


class CaptureError(MCPNetworkForensicsError):
    """Raised when packet capture fails."""
    pass


class FileNotFoundError(MCPNetworkForensicsError):
    """Raised when PCAP file is not found."""
    pass


class InvalidFileError(MCPNetworkForensicsError):
    """Raised when file is not a valid PCAP."""
    pass


class AnalysisError(MCPNetworkForensicsError):
    """Raised when analysis fails."""
    pass


class TsharkNotFoundError(MCPNetworkForensicsError):
    """Raised when tshark is not installed."""
    pass


class ProtocolNotSupportedError(MCPNetworkForensicsError):
    """Raised when protocol is not supported."""
    pass


class FilterError(MCPNetworkForensicsError):
    """Raised when display filter is invalid."""
    pass
