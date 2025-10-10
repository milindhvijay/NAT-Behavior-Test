# NAT Behavior Test

A comprehensive NAT (Network Address Translation) behavior testing tool that implements RFC 5780 standards to determine how your NAT device handles address mappings and packet filtering across UDP, TCP, and TLS protocols.

## Overview

This tool helps network administrators, developers, and security professionals understand their NAT behavior by performing automated tests using the STUN (Session Traversal Utilities for NAT) protocol. It categorizes NAT behavior into standard classifications defined in RFC 5780.

## Features

- **Multiple Protocol Support**: Tests NAT behavior for UDP, TCP, and TLS protocols
- **Dual Stack Testing**: Automatically tests both IPv4 and IPv6 (when available)
- **Network Interface Selection**: Choose specific network interfaces for testing (en0, eth0, Wi-Fi, etc.)
- **Cross-Platform**: Works on macOS, Linux, and Windows with native interface enumeration
- **RFC 5780 Compliant**: Implements standard NAT behavior discovery mechanisms
- **Automated Testing**: Single command runs all tests sequentially
- **Built-in STUN Servers**: Pre-configured list of public STUN servers
- **Custom Server Support**: Option to test against your own STUN server
- **Tabular Summary**: Clean, formatted table showing NAT mapping and filtering behavior

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
2. Display available network interfaces and prompt for selection
3. Prompt you to select a STUN server
4. Automatically run UDP, TCP, and TLS tests for both IPv4 and IPv6
5. Display a comprehensive summary in tabular format

### Interface Selection

When you run the tool, you'll see available network interfaces:

**macOS/Linux:**
```
Available Network Interfaces:
1. Auto-detect (use default interface)
2. en0        IPv4: 192.168.1.100, IPv6: 2001:db8::1
3. en7        IPv4: 10.1.10.2
4. wlan0      IPv4: 172.16.0.50
```

**Windows:**
```
Available Network Interfaces:
1. Auto-detect (use default interface)
2. Ethernet    IPv4: 192.168.1.100
3. Wi-Fi       IPv4: 10.0.0.50, IPv6: 2001:db8::1
```

Select an interface to test NAT behavior through that specific network path. This is useful for:
- Testing different network adapters (Ethernet vs Wi-Fi)
- Comparing NAT behavior across multiple connections
- Testing VPN vs direct connection
- Multi-homed systems with multiple network paths

### Example Output

```
NETWORK CONNECTIVITY
======================================================================
IPv4: Available
IPv6: Available
======================================================================

Available Network Interfaces:
1. Auto-detect (use default interface)
2. en7        IPv4: 10.1.10.2, IPv6: 200::100

Select interface (1-2): 2

Using interface: en7 (IPv4: 10.1.10.2, IPv6: 200::100)

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

==================================================
Testing IPv4
==================================================
Internal: 10.1.10.2:52904
External: 117.242.106.136:52904
Mapping behavior: Endpoint-Independent
Filtering behavior: Address and Port-Dependent

==================================================
Testing IPv6
==================================================
Internal: [200::100]:55832
External: [2001:4490:4e6d:360f:d620:ff:feb1:2b3d]:55832
Mapping behavior: Endpoint-Independent
Filtering behavior: Address and Port-Dependent

... (TCP and TLS tests follow)

==========================================================================================
SUMMARY
==========================================================================================
Protocol           Mapping Behavior                    Filtering Behavior                 
------------------ ----------------------------------- -----------------------------------
UDP (IPv4)         Endpoint-Independent                Address and Port-Dependent         
UDP (IPv6)         Endpoint-Independent                Address and Port-Dependent         
TCP (IPv4)         Address and Port-Dependent          -                                  
TCP (IPv6)         Address and Port-Dependent          -                                  
TLS (IPv4)         Address and Port-Dependent          -                                  
TLS (IPv6)         Address and Port-Dependent          -                                  
==========================================================================================
```

### Advanced Usage

#### Running Individual Protocol Tests

Run tests separately for specific protocols:

```bash
# UDP test only
python3 RFC5780-UDP.py stun.hot-chilli.net

# TCP test only  
python3 RFC5780-TCP.py stun.hot-chilli.net

# TLS test only (uses port 5349 by default)
python3 RFC5780-TLS.py stun.hot-chilli.net

# With custom port
python3 RFC5780-UDP.py stun.example.com 3478
python3 RFC5780-TLS.py stun.example.com 5349
```

#### Specifying Network Interfaces

Test through specific network interfaces:

```bash
# IPv4 only on specific interface
python3 RFC5780-UDP.py stun.hot-chilli.net --interface-ipv4 192.168.1.100

# IPv6 only on specific interface
python3 RFC5780-UDP.py stun.hot-chilli.net --interface-ipv6 2001:db8::1

# Both IPv4 and IPv6 on same interface
python3 RFC5780-UDP.py stun.hot-chilli.net --interface-ipv4 10.1.10.2 --interface-ipv6 200::100

# Skip IPv6 testing
python3 RFC5780-UDP.py stun.hot-chilli.net --skip-ipv6
```

#### All Command-Line Options

**For individual protocol scripts:**
```bash
python3 RFC5780-UDP.py <server> [port] [options]

Arguments:
  server                    STUN server hostname or IP
  port                      Optional custom port (default: 3478 for UDP/TCP, 5349 for TLS)

Options:
  --interface-ipv4 <ip>     Bind to specific IPv4 address
  --interface-ipv6 <ip>     Bind to specific IPv6 address
  --skip-ipv6               Skip IPv6 tests (IPv4 only)
```

**Examples:**
```bash
# Test through WiFi interface on macOS
python3 RFC5780-UDP.py stun.hot-chilli.net --interface-ipv4 10.0.0.50

# Test through specific Ethernet adapter on Windows
python3 RFC5780-TCP.py stun.fitauto.ru --interface-ipv4 192.168.1.100

# Test with custom port and skip IPv6
python3 RFC5780-UDP.py stun.example.com 3479 --skip-ipv6

# Full example with all options
python3 RFC5780-TLS.py stun.hot-chilli.net 5349 --interface-ipv4 10.1.10.2 --interface-ipv6 200::100
```

### Using a Custom STUN Server

Select option 5 when prompted and enter your STUN server:

```
Enter custom STUN server as domain:port (e.g., stun.example.com:3478, default port if omitted): 
```

## How It Works

1. **Connectivity Check**: Validates IPv4 and IPv6 availability
2. **Interface Enumeration**: 
   - macOS/Linux: Parses `ifconfig` output to list network interfaces
   - Windows: Parses `ipconfig` output to list network adapters
   - Groups interfaces by name with their IPv4/IPv6 addresses
3. **Interface Selection**: User chooses which interface to test through
4. **Initial Binding**: Establishes connection to STUN server from selected interface
5. **Mapping Tests**: 
   - Sends requests from same source port to different server addresses
   - Analyzes how external mapping changes
6. **Filtering Tests** (UDP only):
   - Tests packet acceptance from different sources
   - Determines filtering policy
7. **Classification**: Maps results to RFC 5780 behavior categories
8. **Summary Display**: Shows results in clean tabular format

## File Structure

```
NAT-Behavior-Test/
├── start.py              # Main entry point with automated testing
├── RFC5780-UDP.py        # UDP protocol implementation
├── RFC5780-TCP.py        # TCP protocol implementation
├── RFC5780-TLS.py        # TLS protocol implementation
└── README.md             # This file
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
- **VPN Connection**: May show different behavior than direct connection
- **Dual NIC Setup**: Different interfaces may traverse different NAT gateways

## Use Cases

### When to Use Interface Selection

**1. Multi-Homed Systems**
- Compare NAT behavior between Ethernet and Wi-Fi
- Test failover scenarios
- Verify consistent behavior across interfaces

**2. VPN Testing**
- Test NAT behavior with VPN active (tun0, utun, etc.)
- Compare VPN vs direct connection NAT characteristics
- Troubleshoot VPN routing issues

**3. Network Troubleshooting**
- Isolate which network path has NAT issues
- Compare carrier NAT vs home router behavior
- Debug connectivity problems in specific applications

**4. Development & Testing**
- Test application behavior under different NAT types
- Validate WebRTC/VoIP compatibility
- Simulate various network conditions

**5. Security Analysis**
- Verify NAT filtering policies per interface
- Check if different networks have different security postures
- Audit corporate network NAT behavior

## Troubleshooting

**No interfaces detected**:
- Tool falls back to auto-detect mode
- On macOS/Linux: Verify `ifconfig` command works
- On Windows: Verify `ipconfig` command works
- Some systems may require administrator privileges

**IPv6 tests fail**: 
- Your ISP may not support IPv6
- Router may block IPv6 traffic
- Interface may not have IPv6 configured
- Results shown will be IPv4-only

**Cannot bind to selected interface**:
- Interface IP may have changed since selection
- Verify the interface is still active
- Try selecting a different interface or use auto-detect

**All tests fail**:
- Check firewall settings (may block STUN traffic)
- Try a different STUN server
- Verify internet connectivity on selected interface
- Some networks block UDP/TCP ports used by STUN

**Inconsistent results**:
- Some NATs have dynamic behavior
- Network conditions may change between tests
- Different interfaces may have different NAT policies
- Try running tests multiple times

## Technical Details

### Interface Detection Methods

**macOS/Linux:**
- Executes `ifconfig` and parses output
- Extracts interface names (en0, en1, eth0, wlan0, etc.)
- Identifies IPv4 addresses from `inet` lines
- Identifies IPv6 addresses from `inet6` lines (excluding link-local)
- Filters out loopback interfaces

**Windows:**
- Executes `ipconfig` and parses output
- Extracts adapter names (Ethernet, Wi-Fi, etc.)
- Identifies IPv4 from "IPv4 Address" lines
- Identifies IPv6 from "IPv6 Address" lines (excluding link-local)
- Removes zone IDs and (Preferred) suffixes
- Filters out loopback adapters

### Performance Optimizations

- Precompiled regex patterns for fast domain validation
- Efficient transaction ID generation using `random.randbytes()`
- Optimized socket management with proper cleanup
- SSL context reuse for faster TLS retries
- Interface detection cached during startup
- Parallel execution of IPv4 and IPv6 tests within same protocol

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

## References

- [RFC 5780: NAT Behavior Discovery Using STUN](https://tools.ietf.org/html/rfc5780)
- [RFC 5389: Session Traversal Utilities for NAT (STUN)](https://tools.ietf.org/html/rfc5389)
- [RFC 4787: NAT Behavioral Requirements for UDP](https://tools.ietf.org/html/rfc4787)

## Acknowledgments

Built with reference to RFC 5780 standards for NAT behavior discovery and the STUN protocol specification.
