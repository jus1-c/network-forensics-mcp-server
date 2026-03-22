# MCP Network Forensics

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![MCP](https://img.shields.io/badge/MCP-Compatible-green.svg)](https://modelcontextprotocol.io/)

A high-performance MCP Server for Network Forensics that enables AI agents to analyze PCAP files through the Model Context Protocol. Built with direct tshark integration for maximum speed.

## Features

- **High Performance**: Direct tshark subprocess calls (not PyShark) for 26-90x faster analysis
- **Deep Packet Inspection**: Access to all Wireshark dissectors (1000+ protocols)
- **Advanced Filtering**: Support for all Wireshark display filters
- **Protocol Analysis**: Automatic statistics and distribution analysis
- **Security First**: Path validation, size limits, input sanitization
- **Memory Efficient**: Streaming processing for large files (tested with 1M+ packets)
- **Auto-Detection**: Automatically finds tshark installation

## Performance Benchmarks

Tested on a 1.1GB PCAP file with 1,028,287 packets:

| Operation | Time | Optimization |
|-----------|------|--------------|
| Packet Count | 0.6s | `capinfos` (26x faster) |
| Get Summary | 0.2s | `-c` flag (90x faster) |
| Filter HTTP | 13s | Full file scan |
| Protocol Stats | 17s | Full file scan |
| Extract IPs | 11s | Full file scan |

## Requirements

- Python 3.9+
- Wireshark/tshark (4.0+) and capinfos installed
- MCP-compatible client (Claude Desktop, VSCode, Cline, etc.)

## Installation

### 1. Install Wireshark

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install tshark wireshark-common
```

**macOS:**
```bash
brew install wireshark
```

**Windows:**
Download from [wireshark.org](https://www.wireshark.org/download.html)

Verify installation:
```bash
tshark --version
capinfos --version  # Optional, for faster packet counting
```

### 2. Install MCP Server

```bash
# Clone repository
git clone https://github.com/yourusername/mcp-network-forensics.git
cd mcp-network-forensics

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or: venv\Scripts\activate  # Windows

# Install package
pip install -e .
```

## Configuration

### Claude Desktop

Edit `claude_desktop_config.json`:

**macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows:** `%APPDATA%/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "network-forensics": {
      "command": "python",
      "args": ["-m", "mcp_network_forensics"],
      "env": {
        "MCP_MAX_FILE_SIZE": "10737418240",
        "MCP_MAX_PACKETS": "10000",
        "TSHARK_PATH": "/usr/bin/tshark"
      }
    }
  }
}
```

### VSCode (with Cline extension)

Add to your settings:

```json
{
  "mcpServers": {
    "network-forensics": {
      "command": "python",
      "args": ["-m", "mcp_network_forensics"],
      "disabled": false,
      "autoApprove": []
    }
  }
}
```

## Available Tools

### 1. analyze_pcap_file
Analyze a PCAP file and return summary statistics.

**Parameters:**
- `file_path`: Absolute path to PCAP file (required)
- `packet_limit`: Maximum packets to analyze (default: 1000)
- `display_filter`: Optional Wireshark display filter

**Example:**
```json
{
  "file_path": "/home/user/captures/traffic.pcap",
  "packet_limit": 100,
  "display_filter": "ip.addr == 192.168.1.1"
}
```

### 2. get_packet_details
Get detailed information about a specific packet.

**Parameters:**
- `file_path`: Absolute path to PCAP file
- `packet_index`: Index of packet (0-based)
- `include_layers`: Include layer information (default: true)

**Example:**
```json
{
  "file_path": "/home/user/captures/traffic.pcap",
  "packet_index": 0,
  "include_layers": true
}
```

### 3. filter_packets
Filter packets using Wireshark display filter syntax.

**Parameters:**
- `file_path`: Absolute path to PCAP file
- `display_filter`: Wireshark filter (e.g., "tcp.port == 80", "http", "dns.qry.name contains 'google'")
- `max_results`: Maximum results to return (default: 100)

**Example:**
```json
{
  "file_path": "/home/user/captures/traffic.pcap",
  "display_filter": "tcp.flags.syn == 1 and tcp.flags.ack == 0",
  "max_results": 50
}
```

### 4. get_protocol_statistics
Get protocol distribution statistics.

**Parameters:**
- `file_path`: Absolute path to PCAP file
- `packet_limit`: Maximum packets to analyze (default: 1000)

**Example:**
```json
{
  "file_path": "/home/user/captures/traffic.pcap",
  "packet_limit": 1000
}
```

### 5. extract_unique_ips
Extract unique IP addresses from the capture.

**Parameters:**
- `file_path`: Absolute path to PCAP file

**Example:**
```json
{
  "file_path": "/home/user/captures/traffic.pcap"
}
```

## Usage Examples

### Basic Analysis
```
Please analyze this PCAP file and show me the protocol distribution.
File: /home/user/captures/traffic.pcap
```

### Threat Hunting
```
Find all HTTP requests to external IPs in this capture.
File: /home/user/captures/web.pcap
```

### Network Troubleshooting
```
Show me all TCP SYN packets without ACK (possible port scan).
File: /home/user/captures/suspicious.pcap
```

### Deep Inspection
```
Get detailed information about packet 100, including all layers.
File: /home/user/captures/malware.pcap
```

## Security Features

- **Path Validation**: Only absolute paths allowed, no directory traversal
- **File Size Limits**: Configurable max file size (default: 10GB)
- **Packet Limits**: Configurable max packets per request (default: 10,000)
- **Filter Sanitization**: Display filter validation and dangerous character detection
- **Timeout Protection**: Request timeout configuration (default: 300s)

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `MCP_SERVER_NAME` | Server name | mcp-network-forensics |
| `MCP_MAX_FILE_SIZE` | Max file size in bytes | 10737418240 (10GB) |
| `MCP_MAX_PACKETS` | Max packets per request | 10000 |
| `MCP_TIMEOUT` | Request timeout in seconds | 300 |
| `TSHARK_PATH` | Path to tshark binary | auto-detect |

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────┐
│   MCP Client    │────▶│  MCP Server      │────▶│   tshark    │
│ (Claude/VSCode) │     │  (Python/FastMCP)│     │  (Wireshark)│
└─────────────────┘     └──────────────────┘     └─────────────┘
                               │
                               ▼
                        ┌──────────────┐
                        │   PCAP File  │
                        └──────────────┘
```

## Project Structure

```
mcp-network-forensics/
├── src/
│   └── mcp_network_forensics/
│       ├── __init__.py
│       ├── __main__.py          # Entry point
│       ├── server.py            # MCP server with tools
│       ├── config.py            # Configuration
│       ├── exceptions.py        # Custom exceptions
│       ├── capture/
│       │   ├── __init__.py
│       │   ├── file_capture.py  # File capture manager
│       │   └── tshark_wrapper.py # Direct tshark integration
│       ├── models/
│       │   ├── __init__.py
│       │   └── packet.py        # Pydantic models
│       └── utils/
│           ├── __init__.py
│           ├── validators.py    # Input validation
│           └── formatters.py    # Output formatting
├── pyproject.toml
├── requirements.txt
├── requirements-dev.txt
└── README.md
```

## Development

### Setup Development Environment
```bash
pip install -e ".[dev]"
```

### Code Quality
```bash
black src
isort src
flake8 src
mypy src
```

## Troubleshooting

### tshark not found
```bash
# Check installation
which tshark  # Linux/Mac
where tshark  # Windows

# Set path manually
export TSHARK_PATH=/usr/bin/tshark  # Linux/Mac
set TSHARK_PATH=C:\Program Files\Wireshark\tshark.exe  # Windows
```

### Timeout errors on large files
Increase timeout or reduce packet_limit:
```bash
export MCP_TIMEOUT=600
export MCP_MAX_PACKETS=5000
```

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Wireshark](https://www.wireshark.org/) - Network protocol analyzer
- [Model Context Protocol](https://modelcontextprotocol.io/) - MCP specification
- [FastMCP](https://github.com/modelcontextprotocol/python-sdk) - Python MCP SDK

## Support

For issues and feature requests, please use the [GitHub issue tracker](https://github.com/yourusername/mcp-network-forensics/issues).
