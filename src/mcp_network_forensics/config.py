"""Configuration for MCP Network Forensics."""

import os
from dataclasses import dataclass
from typing import Optional


@dataclass
class Config:
    """Configuration class."""
    
    # Server settings
    server_name: str = "mcp-network-forensics"
    transport: str = "stdio"  # stdio, sse
    host: str = "127.0.0.1"
    port: int = 8000
    
    # Security settings
    max_file_size: int = 10 * 1024 * 1024 * 1024  # 10GB
    allowed_extensions: tuple = (".pcap", ".pcapng", ".cap")
    max_packets_per_request: int = 10000
    timeout_seconds: int = 300
    
    # PyShark settings
    tshark_path: Optional[str] = None
    keep_packets: bool = False  # Memory optimization
    
    # Analysis settings
    default_packet_limit: int = 1000
    default_max_results: int = 100
    
    @classmethod
    def from_env(cls) -> "Config":
        """Load configuration from environment variables."""
        return cls(
            server_name=os.getenv("MCP_SERVER_NAME", cls.server_name),
            transport=os.getenv("MCP_TRANSPORT", cls.transport),
            host=os.getenv("MCP_HOST", cls.host),
            port=int(os.getenv("MCP_PORT", cls.port)),
            max_file_size=int(os.getenv("MCP_MAX_FILE_SIZE", cls.max_file_size)),
            max_packets_per_request=int(
                os.getenv("MCP_MAX_PACKETS", cls.max_packets_per_request)
            ),
            timeout_seconds=int(os.getenv("MCP_TIMEOUT", cls.timeout_seconds)),
            tshark_path=os.getenv("TSHARK_PATH"),
            keep_packets=os.getenv("MCP_KEEP_PACKETS", "").lower() == "true",
        )


# Global config instance
config = Config.from_env()
