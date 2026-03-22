"""TShark wrapper for direct command execution."""

import json
import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ..config import config
from ..exceptions import CaptureError, TsharkNotFoundError

logger = logging.getLogger(__name__)


def get_tshark_path() -> str:
    """Get tshark path from config or auto-detect."""
    if config.tshark_path:
        return config.tshark_path
    
    path = shutil.which("tshark")
    if path:
        return path
    
    # Common paths
    common_paths = [
        r"C:\Users\Administrator\scoop\shims\tshark.exe",
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
    ]
    for p in common_paths:
        if Path(p).exists():
            return p
    
    raise TsharkNotFoundError("tshark not found. Please install Wireshark.")


def run_tshark(
    pcap_file: str,
    args: List[str],
    timeout: int = 60
) -> Tuple[str, str, int]:
    """Run tshark command.
    
    Args:
        pcap_file: Path to PCAP file
        args: Additional tshark arguments
        timeout: Command timeout
        
    Returns:
        Tuple of (stdout, stderr, returncode)
    """
    tshark = get_tshark_path()
    cmd = [tshark, "-r", pcap_file] + args
    
    logger.debug(f"Running: {' '.join(cmd)}")
    
    try:
        # Windows-specific flags to prevent console window
        kwargs = {}
        if os.name == 'nt':
            kwargs['creationflags'] = subprocess.CREATE_NO_WINDOW
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            **kwargs
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        raise CaptureError(f"tshark command timed out after {timeout}s")
    except Exception as e:
        raise CaptureError(f"Failed to run tshark: {e}")


def get_packet_count(pcap_file: str) -> int:
    """Get total packet count quickly.
    
    Uses capinfos if available (fastest), otherwise falls back to
    reading frame numbers.
    
    Args:
        pcap_file: Path to PCAP file
        
    Returns:
        Number of packets
    """
    # Try capinfos first (fastest - 0.6s vs 17s for io,phs)
    try:
        import shutil
        capinfos = shutil.which("capinfos")
        if capinfos:
            kwargs = {}
            if os.name == 'nt':
                kwargs['creationflags'] = subprocess.CREATE_NO_WINDOW
            result = subprocess.run(
                [capinfos, "-c", pcap_file],
                capture_output=True,
                text=True,
                timeout=10,
                **kwargs
            )
            if result.returncode == 0:
                # Parse "Number of packets:   1028 k" or "Number of packets = 1234"
                for line in result.stdout.split('\n'):
                    if 'number of packets' in line.lower():
                        # Handle both "=" and ":" formats
                        if '=' in line:
                            count_str = line.split('=')[1].strip()
                        else:
                            count_str = line.split(':')[1].strip()
                        # Remove 'k' suffix if present (means thousands)
                        if 'k' in count_str.lower():
                            count_str = count_str.lower().replace('k', '').strip()
                            return int(float(count_str) * 1000)
                        return int(count_str)
    except Exception as e:
        logger.debug(f"capinfos failed: {e}")
        pass
    
    # Fallback: Get last frame number using tshark
    logger.info("Falling back to tshark for packet count...")
    stdout, stderr, rc = run_tshark(
        pcap_file,
        ["-n", "-T", "fields", "-e", "frame.number"],
        timeout=120
    )
    
    if rc != 0 or not stdout.strip():
        logger.error(f"Failed to count packets: {stderr}")
        return 0
    
    # Get the last frame number
    lines = stdout.strip().split('\n')
    if lines:
        try:
            # Last line should be the highest frame number
            return int(lines[-1].strip())
        except ValueError:
            pass
    
    return len(lines)
    
    # Get the last frame number
    lines = stdout.strip().split('\n')
    if lines:
        try:
            # Last line should be the highest frame number
            return int(lines[-1].strip())
        except ValueError:
            pass
    
    return len(lines)


def _get_packet_count_io_phs(pcap_file: str) -> int:
    """Fallback: Use io,phs statistics (slower)."""
    stdout, stderr, rc = run_tshark(
        pcap_file,
        ["-q", "-z", "io,phs"],
        timeout=60
    )
    
    if rc != 0:
        logger.warning(f"tshark io,phs failed: {stderr}")
        return _count_packets_manual(pcap_file)
    
    # Parse output for frame count
    for line in stdout.split('\n'):
        if 'frames:' in line.lower():
            try:
                parts = line.split()
                for part in parts:
                    if part.lower().startswith('frames:'):
                        return int(part.split(':')[1])
            except (ValueError, IndexError):
                continue
    
    return _count_packets_manual(pcap_file)


def _count_packets_manual(pcap_file: str) -> int:
    """Fallback: count packets with wc -l equivalent."""
    stdout, stderr, rc = run_tshark(
        pcap_file,
        ["-n", "-T", "fields", "-e", "frame.number"],
        timeout=120
    )
    
    if rc != 0:
        logger.error(f"Manual count failed: {stderr}")
        return 0
    
    # Count non-empty lines
    return len([l for l in stdout.strip().split('\n') if l.strip()])


def get_packets_summary(
    pcap_file: str,
    packet_limit: int = 1000,
    display_filter: Optional[str] = None
) -> List[Dict]:
    """Get packet summaries.
    
    Args:
        pcap_file: Path to PCAP file
        packet_limit: Maximum packets to return
        display_filter: Optional display filter
        
    Returns:
        List of packet dictionaries
    """
    args = [
        "-n",  # No name resolution
        "-T", "fields",
        "-e", "frame.number",
        "-e", "frame.time",
        "-e", "frame.protocols",
        "-e", "frame.len",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "tcp.srcport",
        "-e", "tcp.dstport",
        "-e", "udp.srcport",
        "-e", "udp.dstport",
    ]
    
    # Add packet limit - much faster when we don't need all packets
    if not display_filter:
        # If no filter, we can use -c to stop after N packets
        args.extend(["-c", str(packet_limit)])
    
    if display_filter:
        args.extend(["-Y", display_filter])
    
    stdout, stderr, rc = run_tshark(
        pcap_file,
        args,
        timeout=60
    )
    
    if rc != 0:
        raise CaptureError(f"tshark failed: {stderr}")
    
    packets = []
    for i, line in enumerate(stdout.strip().split('\n')):
        if i >= packet_limit:
            break
        
        fields = line.split('\t')
        if len(fields) >= 4:
            packet = {
                "index": int(fields[0]) - 1,  # 0-based
                "timestamp": fields[1] if len(fields) > 1 else None,
                "protocol": fields[2].split(':')[-1] if len(fields) > 2 else "Unknown",
                "length": int(fields[3]) if len(fields) > 3 and fields[3].isdigit() else 0,
                "src_ip": fields[4] if len(fields) > 4 and fields[4] else None,
                "dst_ip": fields[5] if len(fields) > 5 and fields[5] else None,
                "src_port": None,
                "dst_port": None,
            }
            
            # Extract port (TCP or UDP)
            if len(fields) > 6 and fields[6]:
                packet["src_port"] = fields[6]
            elif len(fields) > 8 and fields[8]:
                packet["src_port"] = fields[8]
            
            if len(fields) > 7 and fields[7]:
                packet["dst_port"] = fields[7]
            elif len(fields) > 9 and fields[9]:
                packet["dst_port"] = fields[9]
            
            packets.append(packet)
    
    return packets


def get_protocol_statistics(
    pcap_file: str,
    packet_limit: int = 1000
) -> Dict:
    """Get protocol statistics.
    
    Args:
        pcap_file: Path to PCAP file
        packet_limit: Max packets to analyze
        
    Returns:
        Dict with statistics
    """
    stdout, stderr, rc = run_tshark(
        pcap_file,
        ["-q", "-z", "io,phs"],
        timeout=30
    )
    
    if rc != 0:
        raise CaptureError(f"tshark failed: {stderr}")
    
    protocols = []
    total_frames = 0
    total_bytes = 0
    
    for line in stdout.split('\n'):
        line = line.strip()
        if not line or line.startswith('===') or line.startswith('Protocols'):
            continue
        
        # Parse line like "  TCP      frames:100 bytes:5000"
        if 'frames:' in line and 'bytes:' in line:
            parts = line.split()
            if len(parts) >= 3:
                proto = parts[0]
                try:
                    frames = int([p for p in parts if p.startswith('frames:')][0].split(':')[1])
                    bytes_val = int([p for p in parts if p.startswith('bytes:')][0].split(':')[1])
                    
                    protocols.append({
                        "protocol": proto,
                        "count": frames,
                        "bytes": bytes_val
                    })
                    total_frames += frames
                    total_bytes += bytes_val
                except (IndexError, ValueError):
                    continue
    
    # Calculate percentages
    for proto in protocols:
        proto["percentage"] = round((proto["count"] / total_frames * 100) if total_frames > 0 else 0, 2)
    
    return {
        "total_packets": total_frames,
        "total_bytes": total_bytes,
        "protocols": sorted(protocols, key=lambda x: x["count"], reverse=True)
    }


def get_unique_ips(pcap_file: str) -> Tuple[List[str], List[str]]:
    """Extract unique IP addresses.
    
    Args:
        pcap_file: Path to PCAP file
        
    Returns:
        Tuple of (src_ips, dst_ips)
    """
    args = [
        "-n",
        "-T", "fields",
        "-e", "ip.src",
        "-e", "ip.dst",
    ]
    
    stdout, stderr, rc = run_tshark(pcap_file, args, timeout=60)
    
    if rc != 0:
        raise CaptureError(f"tshark failed: {stderr}")
    
    src_ips = set()
    dst_ips = set()
    
    for line in stdout.strip().split('\n'):
        fields = line.split('\t')
        if len(fields) >= 2:
            if fields[0]:
                src_ips.add(fields[0])
            if fields[1]:
                dst_ips.add(fields[1])
    
    return sorted(list(src_ips)), sorted(list(dst_ips))


def get_packet_detail(
    pcap_file: str,
    packet_index: int,
    include_layers: bool = True
) -> Optional[Dict]:
    """Get detailed packet info.
    
    Args:
        pcap_file: Path to PCAP file
        packet_index: Packet index (0-based)
        include_layers: Include layer details
        
    Returns:
        Packet dict or None
    """
    # Get packet at specific index (tshark uses 1-based)
    args = [
        "-n",
        "-T", "fields",
        "-e", "frame.number",
        "-e", "frame.time",
        "-e", "frame.protocols",
        "-e", "frame.len",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "tcp.srcport",
        "-e", "tcp.dstport",
        "-e", "udp.srcport",
        "-e", "udp.dstport",
    ]
    
    stdout, stderr, rc = run_tshark(
        pcap_file,
        args + ["-Y", f"frame.number == {packet_index + 1}"],
        timeout=30
    )
    
    if rc != 0 or not stdout.strip():
        return None
    
    fields = stdout.strip().split('\t')
    if len(fields) < 4:
        return None
    
    packet = {
        "index": packet_index,
        "timestamp": fields[1] if len(fields) > 1 else None,
        "protocol": fields[2].split(':')[-1] if len(fields) > 2 else "Unknown",
        "length": int(fields[3]) if len(fields) > 3 and fields[3].isdigit() else 0,
        "src_ip": fields[4] if len(fields) > 4 and fields[4] else None,
        "dst_ip": fields[5] if len(fields) > 5 and fields[5] else None,
        "src_port": None,
        "dst_port": None,
        "layers": []
    }
    
    # Extract port
    if len(fields) > 6 and fields[6]:
        packet["src_port"] = fields[6]
    elif len(fields) > 8 and fields[8]:
        packet["src_port"] = fields[8]
    
    if len(fields) > 7 and fields[7]:
        packet["dst_port"] = fields[7]
    elif len(fields) > 9 and fields[9]:
        packet["dst_port"] = fields[9]
    
    if include_layers:
        # Parse layers from frame.protocols (colon-separated list)
        if len(fields) > 2 and fields[2]:
            # frame.protocols format: "eth:ip:tcp:http"
            packet["layers"] = fields[2].split(':')
    
    return packet
