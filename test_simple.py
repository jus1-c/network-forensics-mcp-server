"""Simple test script."""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from mcp_network_forensics.capture.file_capture import FileCaptureManager
from mcp_network_forensics.utils.validators import validate_file_path

file_path = r"C:\Users\Administrator\Documents\Python\Forensics_Tools\network-forensics-mcp-server\challenge.pcapng"

print("=" * 60)
print("Test 1: Basic Analysis")
print("=" * 60)

validated_path = validate_file_path(file_path)
print(f"File: {validated_path}")

with FileCaptureManager(str(validated_path)) as capture:
    total = capture.get_total_packets()
    print(f"Total packets: {total}")
    
    summaries = capture.get_summary(max_packets=5)
    print(f"\nFirst 5 packets:")
    for s in summaries:
        print(f"  [{s.index}] {s.protocol}: {s.src_ip} -> {s.dst_ip}")

print("\n" + "=" * 60)
print("Test 2: Filter HTTP")
print("=" * 60)

with FileCaptureManager(str(validated_path)) as capture:
    results = capture.filter_packets("http", max_results=3)
    print(f"Found {len(results)} HTTP packets")
    for s in results:
        print(f"  [{s.index}] {s.src_ip}:{s.src_port} -> {s.dst_ip}:{s.dst_port}")

print("\n" + "=" * 60)
print("Test 3: Packet Detail")
print("=" * 60)

with FileCaptureManager(str(validated_path)) as capture:
    detail = capture.get_packet_detail(0, include_layers=True)
    print(f"Packet 0: {detail.protocol}")
    print(f"Layers ({len(detail.layers)}):")
    for layer in detail.layers:
        print(f"  - {layer.layer_name}")

print("\n" + "=" * 60)
print("All tests passed!")
print("=" * 60)
