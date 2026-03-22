"""Pydantic models for data structures."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class PacketLayer(BaseModel):
    """Model for a packet layer."""
    layer_name: str = Field(..., description="Name of the layer (e.g., 'IP', 'TCP')")
    fields: Dict[str, Any] = Field(default_factory=dict, description="Layer fields")


class PacketSummary(BaseModel):
    """Summary model for a packet."""
    index: int = Field(..., description="Packet index in capture")
    timestamp: Optional[str] = Field(None, description="Packet timestamp (ISO format)")
    protocol: str = Field(..., description="Highest layer protocol")
    length: int = Field(..., description="Packet length in bytes")
    src_ip: Optional[str] = Field(None, description="Source IP address")
    dst_ip: Optional[str] = Field(None, description="Destination IP address")
    src_port: Optional[str] = Field(None, description="Source port")
    dst_port: Optional[str] = Field(None, description="Destination port")
    info: Optional[str] = Field(None, description="Brief info about packet")


class PacketDetail(PacketSummary):
    """Detailed model for a packet."""
    layers: List[PacketLayer] = Field(default_factory=list, description="Packet layers")
    raw_hex: Optional[str] = Field(None, description="Raw packet data in hex")


class ProtocolStats(BaseModel):
    """Statistics for protocols."""
    protocol: str = Field(..., description="Protocol name")
    count: int = Field(..., description="Number of packets")
    percentage: float = Field(..., description="Percentage of total packets")
    bytes: int = Field(..., description="Total bytes")


class IPStats(BaseModel):
    """Statistics for IP addresses."""
    ip: str = Field(..., description="IP address")
    packets_sent: int = Field(..., description="Packets sent")
    packets_received: int = Field(..., description="Packets received")
    bytes_sent: int = Field(..., description="Bytes sent")
    bytes_received: int = Field(..., description="Bytes received")


class PortStats(BaseModel):
    """Statistics for ports."""
    port: str = Field(..., description="Port number")
    protocol: str = Field(..., description="Protocol (TCP/UDP)")
    packet_count: int = Field(..., description="Number of packets")


class TrafficStatistics(BaseModel):
    """Overall traffic statistics."""
    total_packets: int = Field(..., description="Total number of packets")
    total_bytes: int = Field(..., description="Total bytes")
    duration_seconds: float = Field(..., description="Capture duration")
    start_time: Optional[str] = Field(None, description="Capture start time")
    end_time: Optional[str] = Field(None, description="Capture end time")
    protocols: List[ProtocolStats] = Field(default_factory=list)
    top_src_ips: List[IPStats] = Field(default_factory=list)
    top_dst_ips: List[IPStats] = Field(default_factory=list)
    top_ports: List[PortStats] = Field(default_factory=list)


class Conversation(BaseModel):
    """Model for a network conversation."""
    src_ip: str = Field(..., description="Source IP")
    dst_ip: str = Field(..., description="Destination IP")
    src_port: Optional[str] = Field(None, description="Source port")
    dst_port: Optional[str] = Field(None, description="Destination port")
    protocol: str = Field(..., description="Protocol")
    packet_count: int = Field(..., description="Number of packets")
    byte_count: int = Field(..., description="Total bytes")
    duration_seconds: Optional[float] = Field(None, description="Conversation duration")


class AnalysisResult(BaseModel):
    """Base model for analysis results."""
    success: bool = Field(..., description="Whether analysis succeeded")
    error_message: Optional[str] = Field(None, description="Error message if failed")
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())


class PCAPAnalysisResult(AnalysisResult):
    """Result from PCAP file analysis."""
    file_path: str = Field(..., description="Path to PCAP file")
    total_packets: int = Field(..., description="Total packets in file")
    analyzed_packets: int = Field(..., description="Number of packets analyzed")
    protocols: Dict[str, int] = Field(default_factory=dict)
    sample_packets: List[PacketSummary] = Field(default_factory=list)
    statistics: Optional[TrafficStatistics] = None
    error_message: Optional[str] = Field(None, description="Error message if failed")


class FilterResult(AnalysisResult):
    """Result from packet filtering."""
    total_matching: int = Field(..., description="Total matching packets")
    returned_count: int = Field(..., description="Number of packets returned")
    packets: List[PacketSummary] = Field(default_factory=list)
    filter_expression: str = Field(..., description="Filter expression used")
    error_message: Optional[str] = Field(None, description="Error message if failed")


class AnomalyDetectionResult(AnalysisResult):
    """Result from anomaly detection."""
    anomalies_found: int = Field(..., description="Number of anomalies found")
    anomalies: List[Dict[str, Any]] = Field(default_factory=list)


class ExportResult(AnalysisResult):
    """Result from export operation."""
    output_path: Optional[str] = Field(None, description="Path to exported file")
    records_exported: int = Field(..., description="Number of records exported")
    format: str = Field(..., description="Export format")
