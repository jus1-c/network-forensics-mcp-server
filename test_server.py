"""Test script for MCP Network Forensics Server."""

import asyncio
import json
import sys
from pathlib import Path

# Setup event loop for Windows
try:
    asyncio.get_running_loop()
except RuntimeError:
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from mcp_network_forensics.capture.file_capture import FileCaptureManager
from mcp_network_forensics.utils.validators import validate_file_path


def test_analyze_pcap():
    """Test basic PCAP analysis."""
    print("=" * 60)
    print("TEST: Analyze PCAP File")
    print("=" * 60)
    
    file_path = r"C:\Users\Administrator\Documents\Python\Forensics_Tools\network-forensics-mcp-server\challenge.pcapng"
    
    try:
        # Validate path
        validated_path = validate_file_path(file_path)
        print(f"File validated: {validated_path}")
        
        with FileCaptureManager(str(validated_path)) as capture:
            total_packets = capture.get_total_packets()
            print(f"Total packets in file: {total_packets}")
            
            # Get first 10 packet summaries
            summaries = capture.get_summary(max_packets=10)
            print(f"\nFirst {len(summaries)} packets:")
            print("-" * 60)
            
            for summary in summaries:
                print(f"  Index: {summary.index}")
                print(f"  Timestamp: {summary.timestamp}")
                print(f"  Protocol: {summary.protocol}")
                print(f"  Length: {summary.length}")
                print(f"  Src IP: {summary.src_ip}")
                print(f"  Dst IP: {summary.dst_ip}")
                print(f"  Src Port: {summary.src_port}")
                print(f"  Dst Port: {summary.dst_port}")
                print("-" * 60)
        
        print("[OK] Test PASSED")
        return True
        
    except Exception as e:
        print(f"[FAIL] Test FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_filter_packets():
    """Test packet filtering."""
    print("\n" + "=" * 60)
    print("TEST: Filter Packets (HTTP)")
    print("=" * 60)
    
    file_path = r"C:\Users\Administrator\Documents\Python\Forensics_Tools\network-forensics-mcp-server\challenge.pcapng"
    
    try:
        validated_path = validate_file_path(file_path)
        
        with FileCaptureManager(str(validated_path)) as capture:
            # Filter for HTTP traffic
            print("Filtering for HTTP traffic...")
            summaries = capture.filter_packets(
                display_filter="http",
                max_results=5
            )
            
            print(f"Found {len(summaries)} HTTP packets")
            
            for summary in summaries[:3]:  # Show first 3
                print(f"  Packet {summary.index}: {summary.protocol}")
                print(f"    Src: {summary.src_ip}:{summary.src_port}")
                print(f"    Dst: {summary.dst_ip}:{summary.dst_port}")
            
            # Filter for DNS traffic
            print("\nFiltering for DNS traffic...")
            dns_summaries = capture.filter_packets(
                display_filter="dns",
                max_results=5
            )
            print(f"Found {len(dns_summaries)} DNS packets")
        
        print("[OK] Test PASSED")
        return True
        
    except Exception as e:
        print(f"[FAIL] Test FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_packet_details():
    """Test getting packet details."""
    print("\n" + "=" * 60)
    print("TEST: Get Packet Details")
    print("=" * 60)
    
    file_path = r"C:\Users\Administrator\Documents\Python\Forensics_Tools\network-forensics-mcp-server\challenge.pcapng"
    
    try:
        validated_path = validate_file_path(file_path)
        
        with FileCaptureManager(str(validated_path)) as capture:
            # Get first packet details
            detail = capture.get_packet_detail(
                index=0,
                include_layers=True
            )
            
            if detail:
                print(f"Packet 0 Details:")
                print(f"  Timestamp: {detail.timestamp}")
                print(f"  Protocol: {detail.protocol}")
                print(f"  Length: {detail.length}")
                print(f"  Src IP: {detail.src_ip}")
                print(f"  Dst IP: {detail.dst_ip}")
                print(f"  Layers: {len(detail.layers)}")
                
                if detail.layers:
                    print("  Layer Names:")
                    for layer in detail.layers[:3]:  # Show first 3 layers
                        print(f"    - {layer.get('name', 'Unknown')}")
            else:
                print("No packet found at index 0")
        
        print("[OK] Test PASSED")
        return True
        
    except Exception as e:
        print(f"[FAIL] Test FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_protocol_statistics():
    """Test protocol statistics."""
    print("\n" + "=" * 60)
    print("TEST: Protocol Statistics")
    print("=" * 60)
    
    file_path = r"C:\Users\Administrator\Documents\Python\Forensics_Tools\network-forensics-mcp-server\challenge.pcapng"
    
    try:
        validated_path = validate_file_path(file_path)
        
        with FileCaptureManager(str(validated_path)) as capture:
            total_packets = capture.get_total_packets()
            
            # Count protocols
            protocols = {}
            for packet in capture.iter_packets(packet_limit=1000):
                proto = packet.highest_layer if hasattr(packet, 'highest_layer') else "Unknown"
                protocols[proto] = protocols.get(proto, 0) + 1
            
            print(f"Protocol Distribution (first 1000 packets):")
            print("-" * 60)
            
            for proto, count in sorted(protocols.items(), key=lambda x: x[1], reverse=True):
                percentage = (count / min(1000, total_packets)) * 100
                print(f"  {proto:20s}: {count:5d} ({percentage:5.2f}%)")
        
        print("[OK] Test PASSED")
        return True
        
    except Exception as e:
        print(f"[FAIL] Test FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all tests."""
    print("MCP Network Forensics - Test Suite")
    print("=" * 60)
    print()
    
    results = []
    
    # Run tests
    results.append(("Analyze PCAP", test_analyze_pcap()))
    results.append(("Filter Packets", test_filter_packets()))
    results.append(("Packet Details", test_packet_details()))
    results.append(("Protocol Statistics", test_protocol_statistics()))
    
    # Summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for name, result in results:
        status = "[OK] PASSED" if result else "[FAIL] FAILED"
        print(f"{name:30s}: {status}")
    
    print("-" * 60)
    print(f"Total: {passed}/{total} tests passed")
    print("=" * 60)
    
    return passed == total


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
