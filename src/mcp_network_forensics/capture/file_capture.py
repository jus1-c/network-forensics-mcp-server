"""File capture module for PyShark."""

import asyncio
import logging
import os
import shutil
import subprocess
from contextlib import contextmanager
from pathlib import Path
from typing import Generator, Iterator, List, Optional

import pyshark

from ..config import config
from ..exceptions import CaptureError, TsharkNotFoundError
from ..models.packet import PacketDetail, PacketSummary
from ..utils.formatters import format_timestamp

logger = logging.getLogger(__name__)


def _ensure_event_loop():
    """Ensure an event loop exists for the current thread."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)


def auto_detect_tshark_path() -> Optional[str]:
    """Auto-detect tshark path from common locations.
    
    Returns:
        Path to tshark executable or None if not found
    """
    # 1. Check environment variable
    env_path = os.environ.get("TSHARK_PATH")
    if env_path and Path(env_path).exists():
        logger.info(f"Found tshark via TSHARK_PATH env: {env_path}")
        return env_path
    
    # 2. Check config
    if config.tshark_path and Path(config.tshark_path).exists():
        logger.info(f"Found tshark via config: {config.tshark_path}")
        return config.tshark_path
    
    # 3. Try 'where' on Windows or 'which' on Unix
    try:
        cmd = "where tshark" if os.name == "nt" else "which tshark"
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            path = result.stdout.strip().split('\n')[0]
            logger.info(f"Found tshark via {cmd}: {path}")
            return path
    except Exception:
        pass
    
    # 4. Check common Windows installation paths
    if os.name == "nt":
        common_paths = [
            r"C:\Program Files\Wireshark\tshark.exe",
            r"C:\Program Files (x86)\Wireshark\tshark.exe",
            r"C:\Users\Administrator\scoop\shims\tshark.exe",
        ]
        for path in common_paths:
            if Path(path).exists():
                logger.info(f"Found tshark at common path: {path}")
                return path
    
    # 5. Try 'tshark' directly (if in PATH)
    if shutil.which("tshark"):
        logger.info("Found tshark in PATH")
        return "tshark"
    
    return None


class FileCaptureManager:
    """Manager for file-based packet capture."""
    
    def __init__(self, file_path: str, tshark_path: Optional[str] = None):
        """Initialize file capture manager.
        
        Args:
            file_path: Path to PCAP file
            tshark_path: Optional path to tshark executable (auto-detected if not provided)
        """
        self.file_path = Path(file_path)
        
        # Auto-detect tshark path if not provided
        if tshark_path:
            self.tshark_path = tshark_path
        elif config.tshark_path:
            self.tshark_path = config.tshark_path
        else:
            self.tshark_path = auto_detect_tshark_path()
        
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
        if self.tshark_path is None:
            raise TsharkNotFoundError(
                "tshark not found. Please install Wireshark or set TSHARK_PATH environment variable."
            )
        
        try:
            _ensure_event_loop()
            
            self._capture = pyshark.FileCapture(
                str(self.file_path),
                keep_packets=config.keep_packets,
                tshark_path=self.tshark_path,
            )
            logger.info(f"Opened capture file: {self.file_path} (tshark: {self.tshark_path})")
        except Exception as e:
            if "tshark" in str(e).lower() or "not found" in str(e).lower():
                raise TsharkNotFoundError(
                    f"tshark not found. Please install Wireshark. Error: {e}"
                )
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
