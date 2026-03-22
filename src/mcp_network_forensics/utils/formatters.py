"""Output formatting utilities."""

import json
from datetime import datetime
from typing import Any, Dict, List, Union

import pyshark


def format_timestamp(ts: datetime) -> str:
    """Format timestamp to ISO string."""
    return ts.isoformat() if ts else None


def packet_to_dict(packet: pyshark.Packet, include_layers: bool = True) -> Dict[str, Any]:
    """Convert pyshark packet to dictionary.
    
    Args:
        packet: PyShark packet object
        include_layers: Whether to include layer details
        
    Returns:
        Dictionary representation of packet
    """
    result = {
        "timestamp": format_timestamp(packet.sniff_time),
        "length": int(packet.length) if hasattr(packet, 'length') else 0,
        "protocol": packet.highest_layer if hasattr(packet, 'highest_layer') else "Unknown",
    }
    
    # Add IP info if available
    if hasattr(packet, 'ip'):
        result["src_ip"] = packet.ip.src
        result["dst_ip"] = packet.ip.dst
    
    # Add port info if available
    if hasattr(packet, 'tcp'):
        result["src_port"] = packet.tcp.srcport
        result["dst_port"] = packet.tcp.dstport
    elif hasattr(packet, 'udp'):
        result["src_port"] = packet.udp.srcport
        result["dst_port"] = packet.udp.dstport
    
    # Add layer details if requested
    if include_layers:
        layers = []
        for layer in packet.layers:
            layer_info = {
                "name": layer.layer_name,
                "fields": {}
            }
            # Extract field names and values
            for field_name in layer.field_names:
                try:
                    value = getattr(layer, field_name)
                    # Convert to serializable format
                    if hasattr(value, 'binary_value'):
                        layer_info["fields"][field_name] = {
                            "value": str(value),
                            "binary": value.binary_value.hex() if value.binary_value else None
                        }
                    else:
                        layer_info["fields"][field_name] = str(value)
                except Exception:
                    continue
            layers.append(layer_info)
        result["layers"] = layers
    
    return result


def packets_to_json(packets: List[pyshark.Packet], indent: int = 2) -> str:
    """Convert packets to JSON string.
    
    Args:
        packets: List of packets
        indent: JSON indentation
        
    Returns:
        JSON string
    """
    data = [packet_to_dict(p) for p in packets]
    return json.dumps(data, indent=indent, default=str)


def format_bytes(bytes_val: int) -> str:
    """Format bytes to human-readable string."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_val < 1024.0:
            return f"{bytes_val:.2f} {unit}"
        bytes_val /= 1024.0
    return f"{bytes_val:.2f} PB"


def format_duration(seconds: float) -> str:
    """Format duration to human-readable string."""
    if seconds < 60:
        return f"{seconds:.2f} seconds"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.2f} minutes"
    else:
        hours = seconds / 3600
        return f"{hours:.2f} hours"


def truncate_string(s: str, max_length: int = 100) -> str:
    """Truncate string with ellipsis."""
    if len(s) <= max_length:
        return s
    return s[:max_length-3] + "..."
