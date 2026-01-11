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
- **RFC 5389/8489 Compliant**: Supports modern STUN protocol with XOR-MAPPED-ADDRESS
- **Automated Testing**: Single command runs all tests sequentially
- **Built-in STUN Servers**: Pre-configured list of public STUN servers
- **Custom Server Support**: Option to test against your own STUN server
- **Tabular Summary**: Clean, formatted table showing NAT mapping and filtering behavior
- **Enhanced STUN Attributes**: Parses and displays additional response attributes:
  - XOR-MAPPED-ADDRESS (preferred over legacy MAPPED-ADDRESS)
  - OTHER-ADDRESS (alternate server for NAT testing)
  - RESPONSE-ORIGIN (source of the response)
  - SOFTWARE (server software identification)
- **Exponential Backoff Retry**: Robust retry mechanism for unreliable networks

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
======================================================================
NETWORK CONNECTIVITY
======================================================================
IPv4: Available
IPv6: Available
======================================================================

Available Network Interfaces:
1. Auto-detect (use default interface)
2. Ethernet   IPv4: 91.99.229.254, IPv6: 2a01:4f8:1c1a:98c6::1

Select interface (1-2): 2

Using interface: Ethernet (IPv4: 91.99.229.254, IPv6: 2a01:4f8:1c1a:98c6::1)

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
Using interface: IPv4=91.99.229.254, IPv6=2a01:4f8:1c1a:98c6::1
Using default port: 3478

==================================================
Testing IPv4
==================================================
Internal: 91.99.229.254:60760
External: 91.99.229.254:60760
Server: Coturn-4.5.0.5 'dan Eider'
Other Address: 193.16.218.162:3479
Mapping behavior: Direct
Filtering behavior: Endpoint-Independent

==================================================
Testing IPv6
==================================================
Internal: [2a01:4f8:1c1a:98c6::1]:64275
External: [2a01:4f8:1c1a:98c6::1]:64275
Server: Coturn-4.5.0.5 'dan Eider'
Other Address: [2a01:4f8::1]:3479
Mapping behavior: Direct
Filtering behavior: Endpoint-Independent

######################################################################
# TCP Test
######################################################################

Using STUN server: stun.hot-chilli.net
Using interface: IPv4=91.99.229.254, IPv6=2a01:4f8:1c1a:98c6::1
Using default port: 3478

==================================================
Testing IPv4 TCP
==================================================
Internal: 91.99.229.254:60344
External: 91.99.229.254:60344
Server: Coturn-4.5.0.5 'dan Eider'
TCP Mapping behavior: Direct

==================================================
Testing IPv6 TCP
==================================================
Internal: [2a01:4f8:1c1a:98c6::1]:54475
External: [2a01:4f8:1c1a:98c6::1]:54475
Server: Coturn-4.5.0.5 'dan Eider'
TCP Mapping behavior: Direct

######################################################################
# TLS Test
######################################################################

Using STUN server: stun.hot-chilli.net
Using interface: IPv4=91.99.229.254, IPv6=2a01:4f8:1c1a:98c6::1
Using default port: 5349

==================================================
Testing IPv4 TLS
==================================================
Internal: 91.99.229.254:58364
External: 91.99.229.254:58364
Server: Coturn-4.5.0.5 'dan Eider'
TLS Mapping behavior: Direct

==================================================
Testing IPv6 TLS
==================================================
Internal: [2a01:4f8:1c1a:98c6::1]:64826
External: [2a01:4f8:1c1a:98c6::1]:64826
Server: Coturn-4.5.0.5 'dan Eider'
TLS Mapping behavior: Direct

==========================================================================================
SUMMARY
==========================================================================================
Protocol           Mapping Behavior                    Filtering Behavior
------------------ ----------------------------------- -----------------------------------
UDP (IPv4)         Direct                              Endpoint-Independent
UDP (IPv6)         Direct                              Endpoint-Independent
TCP (IPv4)         Direct                              -
TCP (IPv6)         Direct                              -
TLS (IPv4)         Direct                              -
TLS (IPv6)         Direct                              -
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

# Skip IPv6 testing (IPv4 only)
python3 RFC5780-UDP.py stun.hot-chilli.net --skip-ipv6

# Skip IPv4 testing (IPv6 only)
python3 RFC5780-UDP.py stun.hot-chilli.net --skip-ipv4
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
  --skip-ipv4               Skip IPv4 tests (IPv6 only)
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

# Test IPv6 only (skip IPv4)
python3 RFC5780-UDP.py stun.hot-chilli.net --skip-ipv4

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
├── README.md             # This file
└── TODO.md               # Planned improvements and roadmap
```

## Understanding Results

### Output Fields

- **Internal**: Your local IP address and port
- **External**: Your public (NAT-translated) IP address and port as seen by the STUN server
- **Server**: STUN server software identification (SOFTWARE attribute)
- **Other Address**: Alternate server IP:port for NAT behavior testing (OTHER-ADDRESS attribute)
- **Mapping behavior**: How your NAT assigns external ports
- **Filtering behavior**: Which incoming packets your NAT accepts (UDP only)

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

### When to Skip IP Versions

**Skip IPv4 (--skip-ipv4):**
- Testing IPv6-only networks
- Verifying IPv6 deployment readiness
- Isolating IPv6-specific NAT issues
- Environments where IPv4 is disabled

**Skip IPv6 (--skip-ipv6):**
- IPv6 not available or not configured
- Testing legacy IPv4-only infrastructure
- Isolating IPv4-specific NAT issues
- Faster testing when IPv6 is not relevant

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

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

## References

- [RFC 5780: NAT Behavior Discovery Using STUN](https://tools.ietf.org/html/rfc5780)
- [RFC 8489: Session Traversal Utilities for NAT (STUN)](https://tools.ietf.org/html/rfc8489) - Latest STUN specification
- [RFC 5389: Session Traversal Utilities for NAT (STUN)](https://tools.ietf.org/html/rfc5389) - Original STUN specification
- [RFC 4787: NAT Behavioral Requirements for UDP](https://tools.ietf.org/html/rfc4787)

## Acknowledgments

Built with reference to RFC 5780 standards for NAT behavior discovery and the STUN protocol specification.
