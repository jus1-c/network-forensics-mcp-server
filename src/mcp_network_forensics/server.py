"""MCP Server implementation using FastMCP."""

import json
import logging
from typing import Optional

from mcp.server.fastmcp import FastMCP

from .capture.file_capture import FileCaptureManager
from .config import config
from .models.packet import (
    PCAPAnalysisResult,
    FilterResult,
    PacketDetail,
    PacketSummary,
    TrafficStatistics,
)
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
        JSON string with analysis results including:
        - total_packets: Total packets in file
        - analyzed_packets: Number of packets analyzed
        - protocols: Protocol distribution
        - sample_packets: Sample of packets with details
        - file_path: Path to analyzed file
    """
    try:
        # Validate inputs
        validated_path = validate_file_path(file_path)
        validated_limit = validate_packet_limit(packet_limit, config.default_packet_limit)
        validated_filter = validate_display_filter(display_filter)
        
        logger.info(f"Analyzing PCAP: {file_path}, limit={validated_limit}")
        
        with FileCaptureManager(str(validated_path)) as capture:
            total_packets = capture.get_total_packets()
            
            # Get packet summaries
            summaries = capture.get_summary(max_packets=validated_limit)
            
            # Calculate protocol distribution
            protocols = {}
            for summary in summaries:
                proto = summary.protocol
                protocols[proto] = protocols.get(proto, 0) + 1
            
            result = PCAPAnalysisResult(
                success=True,
                file_path=str(validated_path),
                total_packets=total_packets,
                analyzed_packets=len(summaries),
                protocols=protocols,
                sample_packets=summaries[:20],  # Return first 20 as samples
                error_message=None,
            )
            
            return json.dumps(result.model_dump(), indent=2, default=str)
            
    except Exception as e:
        logger.error(f"Error analyzing PCAP: {e}")
        result = PCAPAnalysisResult(
            success=False,
            file_path=file_path,
            total_packets=0,
            analyzed_packets=0,
            error_message=str(e),
        )
        return json.dumps(result.model_dump(), indent=2, default=str)


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
        JSON string with packet details including:
        - index: Packet index
        - timestamp: Packet timestamp
        - protocol: Highest layer protocol
        - length: Packet length
        - src_ip, dst_ip: Source and destination IPs
        - src_port, dst_port: Source and destination ports
        - layers: Detailed layer information (if requested)
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
                    "success": False,
                    "error": f"Packet {packet_index} not found"
                }, indent=2)
            
            return json.dumps({
                "success": True,
                "packet": detail.model_dump()
            }, indent=2, default=str)
            
    except Exception as e:
        logger.error(f"Error getting packet details: {e}")
        return json.dumps({
            "success": False,
            "error": str(e)
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
        JSON string with filtered packets
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
            
            result = FilterResult(
                success=True,
                total_matching=len(summaries),
                returned_count=len(summaries),
                packets=summaries,
                filter_expression=validated_filter,
                error_message=None,
            )
            
            return json.dumps(result.model_dump(), indent=2, default=str)
            
    except Exception as e:
        logger.error(f"Error filtering packets: {e}")
        result = FilterResult(
            success=False,
            total_matching=0,
            returned_count=0,
            filter_expression=display_filter,
            error_message=str(e),
        )
        return json.dumps(result.model_dump(), indent=2, default=str)


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
        JSON string with protocol statistics
    """
    try:
        validated_path = validate_file_path(file_path)
        validated_limit = validate_packet_limit(packet_limit, config.default_packet_limit)
        
        logger.info(f"Getting protocol stats for {file_path}")
        
        with FileCaptureManager(str(validated_path)) as capture:
            total_packets = capture.get_total_packets()
            
            # Count protocols
            protocols = {}
            total_bytes = 0
            
            for packet in capture.iter_packets(packet_limit=validated_limit):
                proto = packet.highest_layer if hasattr(packet, 'highest_layer') else "Unknown"
                protocols[proto] = protocols.get(proto, 0) + 1
                
                if hasattr(packet, 'length'):
                    total_bytes += int(packet.length)
            
            # Calculate percentages
            stats = []
            for proto, count in sorted(protocols.items(), key=lambda x: x[1], reverse=True):
                stats.append({
                    "protocol": proto,
                    "count": count,
                    "percentage": round(count / min(validated_limit, total_packets) * 100, 2),
                })
            
            return json.dumps({
                "success": True,
                "total_packets": total_packets,
                "analyzed_packets": min(validated_limit, total_packets),
                "total_bytes": total_bytes,
                "protocols": stats,
            }, indent=2)
            
    except Exception as e:
        logger.error(f"Error getting protocol statistics: {e}")
        return json.dumps({
            "success": False,
            "error": str(e)
        }, indent=2)


@mcp.tool()
def extract_unique_ips(file_path: str) -> str:
    """Extract unique IP addresses from PCAP file.
    
    Args:
        file_path: Absolute path to PCAP file
        
    Returns:
        JSON string with unique source and destination IPs
    """
    try:
        validated_path = validate_file_path(file_path)
        
        logger.info(f"Extracting unique IPs from {file_path}")
        
        with FileCaptureManager(str(validated_path)) as capture:
            src_ips = set()
            dst_ips = set()
            
            for packet in capture.iter_packets():
                if hasattr(packet, 'ip'):
                    src_ips.add(packet.ip.src)
                    dst_ips.add(packet.ip.dst)
            
            return json.dumps({
                "success": True,
                "unique_source_ips": sorted(list(src_ips)),
                "unique_destination_ips": sorted(list(dst_ips)),
                "total_unique_ips": len(src_ips.union(dst_ips)),
            }, indent=2)
            
    except Exception as e:
        logger.error(f"Error extracting IPs: {e}")
        return json.dumps({
            "success": False,
            "error": str(e)
        }, indent=2)


def main():
    """Entry point for MCP server."""
    logger.info(f"Starting {config.server_name} server")
    mcp.run()


if __name__ == "__main__":
    main()
