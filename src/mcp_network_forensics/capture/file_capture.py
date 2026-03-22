"""File capture module for PyShark."""

import logging
from contextlib import contextmanager
from pathlib import Path
from typing import Generator, Iterator, List, Optional

import pyshark

from ..config import config
from ..exceptions import CaptureError, TsharkNotFoundError
from ..models.packet import PacketDetail, PacketSummary
from ..utils.formatters import format_timestamp

logger = logging.getLogger(__name__)


class FileCaptureManager:
    """Manager for file-based packet capture."""
    
    def __init__(self, file_path: str):
        """Initialize file capture manager.
        
        Args:
            file_path: Path to PCAP file
        """
        self.file_path = Path(file_path)
        self._capture: Optional[pyshark.FileCapture] = None
        self._total_packets: Optional[int] = None
    
    def __enter__(self):
        """Context manager entry."""
        self.open()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
    
    def open(self) -> None:
        """Open the capture file."""
        try:
            self._capture = pyshark.FileCapture(
                str(self.file_path),
                keep_packets=config.keep_packets,
                tshark_path=config.tshark_path,
            )
            logger.info(f"Opened capture file: {self.file_path}")
        except Exception as e:
            if "tshark" in str(e).lower():
                raise TsharkNotFoundError("tshark not found. Please install Wireshark.")
            raise CaptureError(f"Failed to open capture file: {e}")
    
    def close(self) -> None:
        """Close the capture file."""
        if self._capture:
            try:
                self._capture.close()
                logger.info(f"Closed capture file: {self.file_path}")
            except Exception as e:
                logger.warning(f"Error closing capture: {e}")
            finally:
                self._capture = None
    
    def _get_capture(self) -> pyshark.FileCapture:
        """Get capture object, opening if necessary."""
        if self._capture is None:
            self.open()
        return self._capture
    
    def get_total_packets(self) -> int:
        """Get total number of packets in file.
        
        Returns:
            Total packet count
        """
        if self._total_packets is None:
            try:
                cap = self._get_capture()
                # Force load all packets to get count
                cap.load_packets()
                self._total_packets = len(cap)
            except Exception as e:
                logger.error(f"Error counting packets: {e}")
                self._total_packets = 0
        return self._total_packets
    
    def get_packet(self, index: int) -> Optional[pyshark.Packet]:
        """Get packet at specific index.
        
        Args:
            index: Packet index
            
        Returns:
            Packet or None if not found
        """
        try:
            cap = self._get_capture()
            return cap[index]
        except IndexError:
            return None
        except Exception as e:
            logger.error(f"Error getting packet {index}: {e}")
            return None
    
    def iter_packets(
        self,
        packet_limit: Optional[int] = None,
        display_filter: Optional[str] = None
    ) -> Iterator[pyshark.Packet]:
        """Iterate over packets.
        
        Args:
            packet_limit: Maximum packets to yield
            display_filter: Wireshark display filter
            
        Yields:
            Packet objects
        """
        try:
            if display_filter:
                # Create new capture with filter
                cap = pyshark.FileCapture(
                    str(self.file_path),
                    display_filter=display_filter,
                    keep_packets=False,
                    tshark_path=config.tshark_path,
                )
            else:
                cap = self._get_capture()
            
            count = 0
            for packet in cap:
                yield packet
                count += 1
                if packet_limit and count >= packet_limit:
                    break
            
            if display_filter:
                cap.close()
                
        except Exception as e:
            logger.error(f"Error iterating packets: {e}")
            raise CaptureError(f"Failed to iterate packets: {e}")
    
    def get_summary(self, max_packets: int = 100) -> List[PacketSummary]:
        """Get summary of packets.
        
        Args:
            max_packets: Maximum packets to summarize
            
        Returns:
            List of packet summaries
        """
        summaries = []
        for i, packet in enumerate(self.iter_packets(packet_limit=max_packets)):
            summary = PacketSummary(
                index=i,
                timestamp=format_timestamp(packet.sniff_time),
                protocol=packet.highest_layer if hasattr(packet, 'highest_layer') else "Unknown",
                length=int(packet.length) if hasattr(packet, 'length') else 0,
            )
            
            # Add IP info
            if hasattr(packet, 'ip'):
                summary.src_ip = packet.ip.src
                summary.dst_ip = packet.ip.dst
            
            # Add port info
            if hasattr(packet, 'tcp'):
                summary.src_port = packet.tcp.srcport
                summary.dst_port = packet.tcp.dstport
            elif hasattr(packet, 'udp'):
                summary.src_port = packet.udp.srcport
                summary.dst_port = packet.udp.dstport
            
            summaries.append(summary)
        
        return summaries
    
    def get_packet_detail(
        self,
        index: int,
        include_layers: bool = True
    ) -> Optional[PacketDetail]:
        """Get detailed packet information.
        
        Args:
            index: Packet index
            include_layers: Include layer details
            
        Returns:
            Packet detail or None
        """
        packet = self.get_packet(index)
        if not packet:
            return None
        
        detail = PacketDetail(
            index=index,
            timestamp=format_timestamp(packet.sniff_time),
            protocol=packet.highest_layer if hasattr(packet, 'highest_layer') else "Unknown",
            length=int(packet.length) if hasattr(packet, 'length') else 0,
        )
        
        # Add IP info
        if hasattr(packet, 'ip'):
            detail.src_ip = packet.ip.src
            detail.dst_ip = packet.ip.dst
        
        # Add port info
        if hasattr(packet, 'tcp'):
            detail.src_port = packet.tcp.srcport
            detail.dst_port = packet.tcp.dstport
        elif hasattr(packet, 'udp'):
            detail.src_port = packet.udp.srcport
            detail.dst_port = packet.udp.dstport
        
        # Add layers if requested
        if include_layers:
            from ..utils.formatters import packet_to_dict
            packet_dict = packet_to_dict(packet, include_layers=True)
            detail.layers = packet_dict.get("layers", [])
        
        return detail
    
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
        summaries = []
        for i, packet in enumerate(self.iter_packets(
            packet_limit=max_results,
            display_filter=display_filter
        )):
            summary = PacketSummary(
                index=i,
                timestamp=format_timestamp(packet.sniff_time),
                protocol=packet.highest_layer if hasattr(packet, 'highest_layer') else "Unknown",
                length=int(packet.length) if hasattr(packet, 'length') else 0,
            )
            
            if hasattr(packet, 'ip'):
                summary.src_ip = packet.ip.src
                summary.dst_ip = packet.ip.dst
            
            if hasattr(packet, 'tcp'):
                summary.src_port = packet.tcp.srcport
                summary.dst_port = packet.tcp.dstport
            elif hasattr(packet, 'udp'):
                summary.src_port = packet.udp.srcport
                summary.dst_port = packet.udp.dstport
            
            summaries.append(summary)
        
        return summaries
