"""File capture module using tshark directly."""

import logging
from pathlib import Path
from typing import Iterator, List, Optional

from ..config import config
from ..exceptions import CaptureError, TsharkNotFoundError
from ..models.packet import PacketDetail, PacketSummary
from . import tshark_wrapper

logger = logging.getLogger(__name__)


class FileCaptureManager:
    """Manager for file-based packet capture using tshark directly."""
    
    def __init__(self, file_path: str, tshark_path: Optional[str] = None):
        """Initialize file capture manager.
        
        Args:
            file_path: Path to PCAP file
            tshark_path: Optional path to tshark executable
        """
        self.file_path = Path(file_path)
        self._tshark_path = tshark_path
        self._total_packets: Optional[int] = None
        
        # Set tshark path in wrapper if provided
        if tshark_path:
            from .. import config as app_config
            app_config.config.tshark_path = tshark_path
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        pass
    
    @property
    def tshark_path(self) -> Optional[str]:
        """Get tshark path."""
        return self._tshark_path or tshark_wrapper.get_tshark_path()
    
    def get_total_packets(self) -> int:
        """Get total number of packets in file.
        
        Returns:
            Total packet count
        """
        if self._total_packets is None:
            try:
                self._total_packets = tshark_wrapper.get_packet_count(
                    str(self.file_path)
                )
            except Exception as e:
                logger.error(f"Error counting packets: {e}")
                self._total_packets = 0
        return self._total_packets
    
    def get_packet(self, index: int) -> Optional[PacketDetail]:
        """Get packet at specific index.
        
        Args:
            index: Packet index (0-based)
            
        Returns:
            Packet or None if not found
        """
        try:
            data = tshark_wrapper.get_packet_detail(
                str(self.file_path),
                index,
                include_layers=False
            )
            if not data:
                return None
            
            return PacketDetail(
                index=data["index"],
                timestamp=data.get("timestamp"),
                protocol=data.get("protocol", "Unknown"),
                length=data.get("length", 0),
                src_ip=data.get("src_ip"),
                dst_ip=data.get("dst_ip"),
                src_port=data.get("src_port"),
                dst_port=data.get("dst_port"),
                info=None,
                layers=[],
                raw_hex=None
            )
        except Exception as e:
            logger.error(f"Error getting packet {index}: {e}")
            return None
    
    def get_summary(self, max_packets: int = 100) -> List[PacketSummary]:
        """Get summary of packets.
        
        Args:
            max_packets: Maximum packets to summarize
            
        Returns:
            List of packet summaries
        """
        try:
            packets = tshark_wrapper.get_packets_summary(
                str(self.file_path),
                packet_limit=max_packets
            )
            
            return [
                PacketSummary(
                    index=p["index"],
                    timestamp=p.get("timestamp"),
                    protocol=p.get("protocol", "Unknown"),
                    length=p.get("length", 0),
                    src_ip=p.get("src_ip"),
                    dst_ip=p.get("dst_ip"),
                    src_port=p.get("src_port"),
                    dst_port=p.get("dst_port"),
                    info=None
                )
                for p in packets
            ]
        except Exception as e:
            logger.error(f"Error getting summary: {e}")
            return []
    
    def get_packet_detail(
        self,
        index: int,
        include_layers: bool = True
    ) -> Optional[PacketDetail]:
        """Get detailed packet information.
        
        Args:
            index: Packet index (0-based)
            include_layers: Include layer details
            
        Returns:
            Packet detail or None
        """
        try:
            data = tshark_wrapper.get_packet_detail(
                str(self.file_path),
                index,
                include_layers=include_layers
            )
            
            if not data:
                return None
            
            from ..models.packet import PacketLayer
            
            layers = []
            if include_layers and data.get("layers"):
                for layer_name in data["layers"]:
                    layers.append(PacketLayer(
                        layer_name=layer_name,
                        fields={}
                    ))
            
            return PacketDetail(
                index=data["index"],
                timestamp=data.get("timestamp"),
                protocol=data.get("protocol", "Unknown"),
                length=data.get("length", 0),
                src_ip=data.get("src_ip"),
                dst_ip=data.get("dst_ip"),
                src_port=data.get("src_port"),
                dst_port=data.get("dst_port"),
                info=None,
                layers=layers,
                raw_hex=None
            )
        except Exception as e:
            logger.error(f"Error getting packet detail {index}: {e}")
            return None
    
    def filter_packets(
        self,
        display_filter: str,
        max_results: int = 100
    ) -> List[PacketSummary]:
        """Filter packets using display filter.
        
        Args:
            display_filter: Wireshark display filter
            max_results: Maximum results to return
            
        Returns:
            List of matching packet summaries
        """
        try:
            packets = tshark_wrapper.get_packets_summary(
                str(self.file_path),
                packet_limit=max_results,
                display_filter=display_filter
            )
            
            return [
                PacketSummary(
                    index=p["index"],
                    timestamp=p.get("timestamp"),
                    protocol=p.get("protocol", "Unknown"),
                    length=p.get("length", 0),
                    src_ip=p.get("src_ip"),
                    dst_ip=p.get("dst_ip"),
                    src_port=p.get("src_port"),
                    dst_port=p.get("dst_port"),
                    info=None
                )
                for p in packets
            ]
        except Exception as e:
            logger.error(f"Error filtering packets: {e}")
            return []
    
    def iter_packets(
        self,
        packet_limit: Optional[int] = None,
        display_filter: Optional[str] = None
    ) -> Iterator[dict]:
        """Iterate over packets.
        
        Args:
            packet_limit: Maximum packets to yield
            display_filter: Wireshark display filter
            
        Yields:
            Packet dictionaries
        """
        limit = packet_limit or config.default_packet_limit
        
        try:
            packets = tshark_wrapper.get_packets_summary(
                str(self.file_path),
                packet_limit=limit,
                display_filter=display_filter
            )
            
            for packet in packets:
                yield packet
                
        except Exception as e:
            logger.error(f"Error iterating packets: {e}")
            raise CaptureError(f"Failed to iterate packets: {e}")
