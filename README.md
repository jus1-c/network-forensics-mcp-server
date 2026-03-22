# MCP Network Forensics

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

MCP Server for Network Forensics using PyShark, enabling AI agents to perform deep packet inspection through the Model Context Protocol.

## Features

- **Deep Packet Inspection**: Access to all Wireshark dissectors (1000+ protocols)
- **Object-Oriented Access**: Full packet object access, not just JSON output
- **Protocol Detection**: Automatic recognition of all network protocols
- **Advanced Filtering**: Support for all Wireshark display filters
- **Traffic Analysis**: Protocol statistics, IP distribution, port analysis
- **Security First**: Input validation, path traversal protection, size limits
- **Memory Efficient**: Streaming packet processing for large files

## Requirements

- Python 3.9+
- Wireshark/tshark installed
- MCP-compatible client (Claude Desktop, VSCode, etc.)

## Installation

### 1. Clone Repository

```bash
git clone https://github.com/yourusername/mcp-network-forensics.git
cd mcp-network-forensics
```

### 2. Install Dependencies

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or: venv\Scripts\activate  # Windows

# Install package
pip install -e .
```

### 3. Install Wireshark/tshark

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install tshark
```

**macOS:**
```bash
brew install wireshark
```

**Windows:**
Download from [wireshark.org](https://www.wireshark.org/download.html)

## Configuration

### Claude Desktop

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "network-forensics": {
      "command": "python",
      "args": [
        "-m",
        "mcp_network_forensics"
      ]
    }
  }
}
```

### VSCode

Add to your `settings.json`:

```json
{
  "mcp": {
    "servers": {
      "network-forensics": {
        "type": "stdio",
        "command": "python",
        "args": [
          "-m",
          "mcp_network_forensics"
        ]
      }
    }
  }
}
```

## Available Tools

### analyze_pcap_file
Analyze a PCAP file and return summary statistics.

```json
{
  "file_path": "/path/to/capture.pcap",
  "packet_limit": 1000,
  "display_filter": "ip.addr == 192.168.1.1"
}
```

### get_packet_details
Get detailed information about a specific packet.

```json
{
  "file_path": "/path/to/capture.pcap",
  "packet_index": 0,
  "include_layers": true
}
```

### filter_packets
Filter packets using Wireshark display filter.

```json
{
  "file_path": "/path/to/capture.pcap",
  "display_filter": "tcp.port == 80",
  "max_results": 100
}
```

### get_protocol_statistics
Get protocol distribution statistics.

```json
{
  "file_path": "/path/to/capture.pcap",
  "packet_limit": 1000
}
```

### extract_unique_ips
Extract unique IP addresses.

```json
{
  "file_path": "/path/to/capture.pcap"
}
```

## Usage Examples

### Basic Analysis

```
Please analyze this PCAP file: /home/user/captures/traffic.pcap
```

### Protocol-Specific Analysis

```
Show me all HTTP requests in /home/user/captures/web.pcap
```

### Filter and Inspect

```
Filter packets to port 443 in /home/user/captures/ssl.pcap and show me packet 5 details
```

## Security Features

- **Path Validation**: Only absolute paths allowed, no traversal attacks
- **File Size Limits**: Configurable max file size (default: 10GB)
- **Packet Limits**: Configurable max packets per request (default: 10,000)
- **Filter Sanitization**: Display filter validation and dangerous character detection
- **Timeout Protection**: Request timeout configuration

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `MCP_SERVER_NAME` | Server name | mcp-network-forensics |
| `MCP_MAX_FILE_SIZE` | Max file size in bytes | 10737418240 (10GB) |
| `MCP_MAX_PACKETS` | Max packets per request | 10000 |
| `MCP_TIMEOUT` | Request timeout in seconds | 300 |
| `TSHARK_PATH` | Path to tshark binary | auto-detect |

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
│       │   └── file_capture.py  # PyShark wrapper
│       ├── models/
│       │   └── packet.py        # Pydantic models
│       └── utils/
│           ├── validators.py    # Input validation
│           └── formatters.py    # Output formatting
├── tests/
├── docs/
├── pyproject.toml
├── requirements.txt
└── README.md
```

## Development

### Setup Development Environment

```bash
pip install -e ".[dev]"
```

### Run Tests

```bash
pytest
```

### Code Formatting

```bash
black src tests
isort src tests
```

### Type Checking

```bash
mypy src
```

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) for details.

## Acknowledgments

- [PyShark](https://github.com/KimiNewt/pyshark) - Python wrapper for tshark
- [Model Context Protocol](https://modelcontextprotocol.io/) - MCP specification
- [Wireshark](https://www.wireshark.org/) - Network protocol analyzer
