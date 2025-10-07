# NAT Behavior Test

A comprehensive NAT (Network Address Translation) behavior testing tool that implements RFC 5780 standards to determine how your NAT device handles address mappings and packet filtering across UDP, TCP, and TLS protocols.

## Overview

This tool helps network administrators, developers, and security professionals understand their NAT behavior by performing automated tests using the STUN (Session Traversal Utilities for NAT) protocol. It categorizes NAT behavior into standard classifications defined in RFC 5780.

## Features

- **Multiple Protocol Support**: Tests NAT behavior for UDP, TCP, and TLS protocols
- **Dual Stack Testing**: Automatically tests both IPv4 and IPv6 (when available)
- **RFC 5780 Compliant**: Implements standard NAT behavior discovery mechanisms
- **Automated Testing**: Single command runs all tests sequentially
- **Built-in STUN Servers**: Pre-configured list of public STUN servers
- **Custom Server Support**: Option to test against your own STUN server
- **Detailed Summary**: Clear results showing NAT mapping and filtering behavior

## NAT Behavior Classifications

### Mapping Behavior
- **Direct**: No NAT (public IP address)
- **Endpoint-Independent**: Same external mapping regardless of destination
- **Address-Dependent**: External mapping changes based on destination IP
- **Address and Port-Dependent**: External mapping changes based on destination IP and port

### Filtering Behavior (UDP only)
- **Endpoint-Independent**: Accepts packets from any source
- **Address-Dependent**: Only accepts packets from contacted IPs
- **Address and Port-Dependent**: Only accepts packets from contacted IP:port pairs

## Requirements

- Python 3.7 or higher
- Internet connectivity (IPv4 required, IPv6 optional)
- No external dependencies (uses Python standard library only)

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/NAT-Behavior-Test.git
cd NAT-Behavior-Test

# Run directly (no installation needed)
python3 start.py
```

## Usage

### Quick Start

```bash
python3 start.py
```

The program will:
1. Check IPv4/IPv6 connectivity
2. Prompt you to select a STUN server
3. Automatically run UDP, TCP, and TLS tests
4. Display a comprehensive summary

### Example Output

```
NETWORK CONNECTIVITY
======================================================================
IPv4: Available
IPv6: Available
======================================================================

Select STUN server:
1. stun.hot-chilli.net
2. stun.fitauto.ru
3. stun.internetcalls.com
4. stun.voip.aebc.com
5. Custom Server
Enter STUN server number (1-5): 1

######################################################################
# UDP Test
######################################################################
Using STUN server: stun.hot-chilli.net
Internal: 192.168.1.100:54321
External: 203.0.113.45:54321
Mapping behavior: Endpoint-Independent
Filtering behavior: Address and Port-Dependent

... (TCP and TLS tests follow)

======================================================================
SUMMARY
======================================================================
UDP:
  IPv4:
    Mapping:    Endpoint-Independent
    Filtering:  Address and Port-Dependent
  IPv6:
    Mapping:    Endpoint-Independent
    Filtering:  Address and Port-Dependent
TCP:
  IPv4:
    Mapping:    Address and Port-Dependent
  IPv6:
    Mapping:    Address and Port-Dependent
TLS:
  IPv4:
    Mapping:    Address and Port-Dependent
  IPv6:
    Mapping:    Address and Port-Dependent
======================================================================
```

### Running Individual Protocol Tests

If you need to run tests separately:

```bash
# UDP test only
python3 RFC5780-UDP.py stun.hot-chilli.net

# TCP test only  
python3 RFC5780-TCP.py stun.hot-chilli.net

# TLS test only
python3 RFC5780-TLS.py stun.hot-chilli.net

# With custom port
python3 RFC5780-UDP.py stun.example.com 3478
```

### Using a Custom STUN Server

Select option 5 when prompted and enter your STUN server:

```
Enter custom STUN server as domain:port (e.g., stun.example.com:3478, default port if omitted): 
```

## How It Works

1. **Connectivity Check**: Validates IPv4 and IPv6 availability
2. **Initial Binding**: Establishes connection to STUN server
3. **Mapping Tests**: 
   - Sends requests from same source port to different server addresses
   - Analyzes how external mapping changes
4. **Filtering Tests** (UDP only):
   - Tests packet acceptance from different sources
   - Determines filtering policy
5. **Classification**: Maps results to RFC 5780 behavior categories

## File Structure

```
NAT-Behavior-Test/
├── start.py              # Main entry point with automated testing
├── RFC5780-UDP.py        # UDP protocol implementation
├── RFC5780-TCP.py        # TCP protocol implementation
├── RFC5780-TLS.py        # TLS protocol implementation
└── README.md            # This file
```

## Understanding Results

### What Your Results Mean

- **Endpoint-Independent Mapping**: Best for peer-to-peer applications (VoIP, gaming, WebRTC)
- **Address/Port-Dependent**: More restrictive, may cause issues with some applications
- **Strict Filtering**: Provides better security but may block legitimate traffic
- **Permissive Filtering**: Better connectivity but potentially less secure

### Common Scenarios

- **Home Router**: Usually Endpoint-Independent mapping with Address-Port-Dependent filtering
- **Corporate Firewall**: Often Address-Port-Dependent mapping with strict filtering
- **Mobile Carrier NAT**: Typically highly restrictive on both mapping and filtering

## Troubleshooting

**IPv6 tests fail**: 
- Your ISP may not support IPv6
- Router may block IPv6 traffic
- Results shown will be IPv4-only

**All tests fail**:
- Check firewall settings
- Try a different STUN server
- Verify internet connectivity

**Inconsistent results**:
- Some NATs have dynamic behavior
- Network conditions may change between tests
- Try running tests multiple times

## Performance Optimizations

- Precompiled regex patterns for fast domain validation
- Efficient transaction ID generation using `random.randbytes()`
- Optimized socket management with proper cleanup
- SSL context reuse for faster TLS retries

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

## References

- [RFC 5780: NAT Behavior Discovery Using STUN](https://tools.ietf.org/html/rfc5780)
- [RFC 5389: Session Traversal Utilities for NAT (STUN)](https://tools.ietf.org/html/rfc5389)
- [RFC 4787: NAT Behavioral Requirements for UDP](https://tools.ietf.org/html/rfc4787)

## Acknowledgments

Built with reference to RFC 5780 standards for NAT behavior discovery and the STUN protocol specification.
