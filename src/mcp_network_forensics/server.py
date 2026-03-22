"""MCP Server implementation using FastMCP."""

import json
import logging
from typing import List, Optional

from mcp.server.fastmcp import FastMCP

from .capture.file_capture import FileCaptureManager
from .config import config
from .utils.validators import (
    validate_display_filter,
    validate_file_path,
    validate_packet_limit,
)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Create MCP server
mcp = FastMCP(config.server_name)


@mcp.tool()
def analyze_pcap_file(
    file_path: str,
    packet_limit: Optional[int] = None,
    display_filter: Optional[str] = None
) -> str:
    """Analyze a PCAP file and return summary statistics.
    
    Args:
        file_path: Absolute path to PCAP file
        packet_limit: Maximum packets to analyze (default: 1000)
        display_filter: Optional Wireshark display filter
        
    Returns:
        JSON with status and analysis results
    """
    try:
        validated_path = validate_file_path(file_path)
        validated_limit = validate_packet_limit(packet_limit, config.default_packet_limit)
        validated_filter = validate_display_filter(display_filter)
        
        logger.info(f"Analyzing PCAP: {file_path}, limit={validated_limit}")
        
        with FileCaptureManager(str(validated_path)) as capture:
            total_packets = capture.get_total_packets()
            summaries = capture.get_summary(max_packets=validated_limit)
            
            protocols = {}
            for summary in summaries:
                proto = summary.protocol
                protocols[proto] = protocols.get(proto, 0) + 1
            
            return json.dumps({
                "status": "success",
                "data": {
                    "file_path": str(validated_path),
                    "total_packets": total_packets,
                    "analyzed_packets": len(summaries),
                    "protocols": protocols,
                    "sample_packets": [s.model_dump() for s in summaries[:20]],
                }
            }, indent=2, default=str)
            
    except Exception as e:
        logger.error(f"Error analyzing PCAP: {e}")
        return json.dumps({
            "status": "error",
            "message": str(e)
        }, indent=2)


@mcp.tool()
def get_packet_details(
    file_path: str,
    packet_index: int,
    include_layers: bool = True
) -> str:
    """Get detailed information about a specific packet.
    
    Args:
        file_path: Absolute path to PCAP file
        packet_index: Index of packet to retrieve
        include_layers: Include detailed layer information (default: True)
        
    Returns:
        JSON with packet details or error
    """
    try:
        validated_path = validate_file_path(file_path)
        
        logger.info(f"Getting packet {packet_index} from {file_path}")
        
        with FileCaptureManager(str(validated_path)) as capture:
            detail = capture.get_packet_detail(
                index=packet_index,
                include_layers=include_layers
            )
            
            if not detail:
                return json.dumps({
                    "status": "error",
                    "message": f"Packet {packet_index} not found"
                }, indent=2)
            
            return json.dumps({
                "status": "success",
                "data": detail.model_dump()
            }, indent=2, default=str)
            
    except Exception as e:
        logger.error(f"Error getting packet details: {e}")
        return json.dumps({
            "status": "error",
            "message": str(e)
        }, indent=2)


@mcp.tool()
def filter_packets(
    file_path: str,
    display_filter: str,
    max_results: Optional[int] = None
) -> str:
    """Filter packets using Wireshark display filter.
    
    Supports all standard Wireshark display filters:
    - ip.addr == 192.168.1.1
    - tcp.port == 80
    - http.request.method == "GET"
    - dns.qry.name contains "malware"
    
    Args:
        file_path: Absolute path to PCAP file
        display_filter: Wireshark display filter expression
        max_results: Maximum results to return (default: 100)
        
    Returns:
        JSON with filtered packets
    """
    try:
        validated_path = validate_file_path(file_path)
        validated_filter = validate_display_filter(display_filter)
        validated_limit = validate_packet_limit(max_results, config.default_max_results)
        
        if not validated_filter:
            raise ValueError("Display filter cannot be empty")
        
        logger.info(f"Filtering {file_path} with filter: {validated_filter}")
        
        with FileCaptureManager(str(validated_path)) as capture:
            summaries = capture.filter_packets(
                display_filter=validated_filter,
                max_results=validated_limit
            )
            
            return json.dumps({
                "total_pages": 1,
                "pages": [{
                    "page": 1,
                    "total_matching": len(summaries),
                    "returned_count": len(summaries),
                    "filter_expression": validated_filter,
                    "packets": [s.model_dump() for s in summaries]
                }]
            }, indent=2, default=str)
            
    except Exception as e:
        logger.error(f"Error filtering packets: {e}")
        return json.dumps({
            "status": "error",
            "message": str(e)
        }, indent=2)


@mcp.tool()
def get_protocol_statistics(
    file_path: str,
    packet_limit: Optional[int] = None
) -> str:
    """Get protocol distribution statistics from PCAP file.
    
    Args:
        file_path: Absolute path to PCAP file
        packet_limit: Maximum packets to analyze (default: 1000)
        
    Returns:
        JSON with protocol statistics
    """
    try:
        validated_path = validate_file_path(file_path)
        validated_limit = validate_packet_limit(packet_limit, config.default_packet_limit)
        
        logger.info(f"Getting protocol stats for {file_path}")
        
        # Use tshark_wrapper directly for better performance
        from .capture import tshark_wrapper
        stats = tshark_wrapper.get_protocol_statistics(
            str(validated_path),
            packet_limit=validated_limit
        )
        
        return json.dumps({
            "status": "success",
            "data": stats
        }, indent=2)
            
    except Exception as e:
        logger.error(f"Error getting protocol statistics: {e}")
        return json.dumps({
            "status": "error",
            "message": str(e)
        }, indent=2)


@mcp.tool()
def extract_unique_ips(file_path: str) -> str:
    """Extract unique IP addresses from PCAP file.
    
    Args:
        file_path: Absolute path to PCAP file
        
    Returns:
        JSON with unique source and destination IPs
    """
    try:
        validated_path = validate_file_path(file_path)
        
        logger.info(f"Extracting unique IPs from {file_path}")
        
        # Use tshark_wrapper directly
        from .capture import tshark_wrapper
        src_ips, dst_ips = tshark_wrapper.get_unique_ips(str(validated_path))
        
        return json.dumps({
            "status": "success",
            "data": {
                "unique_source_ips": src_ips,
                "unique_destination_ips": dst_ips,
                "total_unique_ips": len(set(src_ips + dst_ips)),
            }
        }, indent=2)
            
    except Exception as e:
        logger.error(f"Error extracting IPs: {e}")
        return json.dumps({
            "status": "error",
            "message": str(e)
        }, indent=2)


@mcp.tool()
def extract_packet_fields(
    file_path: str,
    fields: List[str],
    display_filter: Optional[str] = None,
    packet_limit: Optional[int] = 100
) -> str:
    """Extract arbitrary fields from packets.
    
    Query any field supported by tshark/wireshark. Useful for extracting
    protocol-specific data like DNS queries, HTTP headers, TLS SNI, etc.
    
    Common fields:
    - DNS: dns.qry.name, dns.qry.type, dns.resp.name, dns.resp.type
    - HTTP: http.request.uri, http.host, http.request.method, http.user_agent
    - TLS: tls.handshake.extensions_server_name (SNI)
    - TCP: tcp.flags, tcp.seq, tcp.ack
    - IP: ip.ttl, ip.id, ip.flags
    - Frame: frame.time_delta, frame.cap_len
    - Data: data.data (raw payload in hex)
    
    Args:
        file_path: Absolute path to PCAP file
        fields: List of field names (e.g., ["dns.qry.name", "dns.qry.type"])
        display_filter: Optional Wireshark display filter
        packet_limit: Maximum packets to return (default: 100)
        
    Returns:
        JSON with extracted field values
    """
    try:
        validated_path = validate_file_path(file_path)
        validated_limit = validate_packet_limit(packet_limit, 100)
        
        if not fields:
            return json.dumps({
                "status": "error",
                "message": "At least one field must be specified"
            }, indent=2)
        
        logger.info(f"Extracting fields {fields} from {file_path}")
        
        from .capture import tshark_wrapper
        results = tshark_wrapper.extract_fields(
            str(validated_path),
            fields=fields,
            display_filter=display_filter,
            packet_limit=validated_limit
        )
        
        return json.dumps({
            "status": "success",
            "data": {
                "fields": fields,
                "count": len(results),
                "results": results
            }
        }, indent=2)
        
    except Exception as e:
        logger.error(f"Error extracting fields: {e}")
        return json.dumps({
            "status": "error",
            "message": str(e)
        }, indent=2)


@mcp.tool()
def extract_packet_payload(
    file_path: str,
    packet_index: Optional[int] = None,
    display_filter: Optional[str] = None,
    max_packets: int = 10
) -> str:
    """Extract raw payload data from packets.
    
    Extracts the raw data payload in hexadecimal format.
    Useful for analyzing binary protocols, extracting files, or debugging.
    
    Args:
        file_path: Absolute path to PCAP file
        packet_index: Specific packet index (0-based, optional)
        display_filter: Filter to apply (e.g., "tcp.port == 80", optional)
        max_packets: Maximum packets to extract (default: 10)
        
    Returns:
        JSON with packet indices and payload data in hex
    """
    try:
        validated_path = validate_file_path(file_path)
        
        logger.info(f"Extracting payload from {file_path}")
        
        from .capture import tshark_wrapper
        results = tshark_wrapper.extract_payload(
            str(validated_path),
            packet_index=packet_index,
            display_filter=display_filter,
            max_packets=max_packets
        )
        
        return json.dumps({
            "status": "success",
            "data": {
                "count": len(results),
                "packets": results
            }
        }, indent=2)
        
    except Exception as e:
        logger.error(f"Error extracting payload: {e}")
        return json.dumps({
            "status": "error",
            "message": str(e)
        }, indent=2)


def main():
    """Entry point for MCP server."""
    logger.info(f"Starting {config.server_name} server")
    mcp.run()


if __name__ == "__main__":
    main()
