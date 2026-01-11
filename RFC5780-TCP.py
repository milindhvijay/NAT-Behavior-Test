import socket
import struct
import random
import time
import sys

# Constants for STUN Message
MAGIC_COOKIE = 0x2112A442
BINDING_REQUEST = 0x0001

# STUN Attribute Types
ATTR_MAPPED_ADDRESS = 0x0001
ATTR_RESPONSE_ADDRESS = 0x0002
ATTR_CHANGE_REQUEST = 0x0003
ATTR_SOURCE_ADDRESS = 0x0004
ATTR_CHANGED_ADDRESS = 0x0005
ATTR_XOR_MAPPED_ADDRESS = 0x0020
ATTR_SOFTWARE = 0x8022
ATTR_RESPONSE_ORIGIN = 0x802B
ATTR_OTHER_ADDRESS = 0x802C

def build_binding_request():
    """Generate a STUN Binding Request with random transaction ID"""
    transaction_id = random.randbytes(12)
    message_type = struct.pack('!H', BINDING_REQUEST)
    message_length = struct.pack('!H', 0)  # No attributes, thus length is 0
    magic_cookie = struct.pack('!I', MAGIC_COOKIE)
    return message_type + message_length + magic_cookie + transaction_id

def parse_stun_response(response):
    """
    Parse STUN response and extract mapped address.
    Supports both MAPPED-ADDRESS and XOR-MAPPED-ADDRESS (preferred).
    Also extracts OTHER-ADDRESS and RESPONSE-ORIGIN if present.
    """
    if len(response) < 20:
        return None

    try:
        message_type, message_length, magic = struct.unpack('!HHI', response[:8])
        transaction_id = response[8:20]
        attributes = response[20:]

        # Check for Binding Success Response
        if message_type != 0x0101:
            return None

        result = {
            'mapped_address': None,
            'xor_mapped_address': None,
            'other_address': None,
            'response_origin': None,
            'software': None
        }

        i = 0
        while i < len(attributes):
            if i + 4 > len(attributes):
                break
            attribute_type, attribute_length = struct.unpack('!HH', attributes[i:i+4])
            i += 4
            if i + attribute_length > len(attributes):
                break

            attr_data = attributes[i:i+attribute_length]

            if attribute_type == ATTR_MAPPED_ADDRESS:
                result['mapped_address'] = parse_address_attribute(attr_data)
            
            elif attribute_type == ATTR_XOR_MAPPED_ADDRESS:
                result['xor_mapped_address'] = parse_xor_address_attribute(attr_data, transaction_id)
            
            elif attribute_type == ATTR_OTHER_ADDRESS:
                result['other_address'] = parse_xor_address_attribute(attr_data, transaction_id)
            
            elif attribute_type == ATTR_RESPONSE_ORIGIN:
                result['response_origin'] = parse_xor_address_attribute(attr_data, transaction_id)
            
            elif attribute_type == ATTR_SOFTWARE:
                try:
                    result['software'] = attr_data.decode('utf-8').rstrip('\x00')
                except:
                    pass

            # Move to next attribute (with padding to 4-byte boundary)
            i += attribute_length
            if attribute_length % 4 != 0:
                i += 4 - (attribute_length % 4)

        # Prefer XOR-MAPPED-ADDRESS over MAPPED-ADDRESS (RFC 5389 recommendation)
        mapped = result['xor_mapped_address'] or result['mapped_address']
        
        if mapped:
            return {
                'address': mapped,
                'other_address': result['other_address'],
                'response_origin': result['response_origin'],
                'software': result['software']
            }
        return None

    except Exception as e:
        return None

def parse_address_attribute(attr_data):
    """Parse MAPPED-ADDRESS attribute (non-XORed)"""
    if len(attr_data) < 8:
        return None
    
    family = struct.unpack('!B', attr_data[1:2])[0]
    port = struct.unpack('!H', attr_data[2:4])[0]
    
    if family == 0x01:  # IPv4
        ip = socket.inet_ntoa(attr_data[4:8])
        return (ip, port)
    elif family == 0x02 and len(attr_data) >= 20:  # IPv6
        ip = socket.inet_ntop(socket.AF_INET6, attr_data[4:20])
        return (ip, port)
    return None

def parse_xor_address_attribute(attr_data, transaction_id):
    """Parse XOR-MAPPED-ADDRESS attribute (XORed with magic cookie)"""
    if len(attr_data) < 8:
        return None
    
    family = struct.unpack('!B', attr_data[1:2])[0]
    xored_port = struct.unpack('!H', attr_data[2:4])[0]
    
    # XOR port with upper 16 bits of magic cookie
    port = xored_port ^ (MAGIC_COOKIE >> 16)
    
    if family == 0x01:  # IPv4
        xored_ip = attr_data[4:8]
        magic_bytes = struct.pack('!I', MAGIC_COOKIE)
        ip_bytes = bytes(a ^ b for a, b in zip(xored_ip, magic_bytes))
        ip = socket.inet_ntoa(ip_bytes)
        return (ip, port)
    elif family == 0x02 and len(attr_data) >= 20:  # IPv6
        xored_ip = attr_data[4:20]
        magic_bytes = struct.pack('!I', MAGIC_COOKIE) + transaction_id
        ip_bytes = bytes(a ^ b for a, b in zip(xored_ip, magic_bytes))
        ip = socket.inet_ntop(socket.AF_INET6, ip_bytes)
        return (ip, port)
    return None

def send_tcp_stun_request(stun_host, stun_port, source_ip, timeout=5, retries=5, use_backoff=True):
    """Send TCP STUN request with exponential backoff retry logic"""
    sock = None
    base_delay = 0.5  # Initial delay for exponential backoff
    
    for attempt in range(retries):
        try:
            source_port = random.randint(49152, 65535)
            sock = socket.socket(socket.AF_INET6 if ':' in source_ip else socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.bind((source_ip, source_port))
            sock.connect((stun_host, stun_port))

            message = build_binding_request()
            sock.sendall(message)

            response = sock.recv(2048)
            parsed_response = parse_stun_response(response)
            sock.close()
            return parsed_response, source_ip, source_port
        except socket.error:
            if sock:
                sock.close()
            if use_backoff:
                # Exponential backoff: 0.5s, 1s, 2s, 4s...
                delay = base_delay * (2 ** attempt)
                time.sleep(min(delay, 8))  # Cap at 8 seconds
    return None, None, None

def check_ipv6_connectivity():
    """Check if the host can access IPv6 sites"""
    try:
        # Try to connect to Google's IPv6 DNS server
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        sock.settimeout(2)
        sock.connect(("2001:4860:4860::8888", 80))
        sock.close()
        return True
    except Exception:
        return False

def get_source_ip(use_ipv6=False, interface_ip=None):
    # If interface IP is provided, use it directly
    if interface_ip:
        return interface_ip
    
    try:
        if use_ipv6:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            sock.connect(("2001:4860:4860::8888", 80))
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.connect(("8.8.8.8", 80))
        source_ip = sock.getsockname()[0]
        sock.close()
        return source_ip
    except Exception as e:
        print(f"Error getting source IP for {'IPv6' if use_ipv6 else 'IPv4'}: {e}")
        return None

def test_stun(server, port, use_ipv6=False, interface_ip=None):
    """Test STUN binding and return external address information"""
    source_ip = get_source_ip(use_ipv6, interface_ip)
    if not source_ip:
        return None, None, None, None, None
        
    response, source_ip, source_port = send_tcp_stun_request(server, port, source_ip)

    if response and response.get('address'):
        external_ip, external_port = response['address']
        other_address = response.get('other_address')
        software = response.get('software')
        
        if ':' in (source_ip or ''):
            print(f"Internal: [{source_ip}]:{source_port}")
            print(f"External: [{external_ip}]:{external_port}")
        else:
            print(f"Internal: {source_ip}:{source_port}")
            print(f"External: {external_ip}:{external_port}")
        
        if software:
            print(f"Server: {software}")
        if other_address:
            print(f"Other Address: {other_address[0]}:{other_address[1]}")
            
        return external_ip, external_port, source_ip, source_port, other_address
    else:
        print(f"Failed to get STUN response")
        return None, None, None, None, None

def get_mapped_address(response):
    """Extract mapped address from response (handles both old and new format)"""
    if response is None:
        return None
    if isinstance(response, dict):
        return response.get('address')
    return response

def tcp_mapping_behavior(stun_host, stun_port, source_ip):
    """Determine TCP NAT mapping behavior per RFC 5780"""
    # Test 1: Send to primary STUN server
    response1, _, source_port1 = send_tcp_stun_request(stun_host, stun_port, source_ip)
    mapped1 = get_mapped_address(response1)
    time.sleep(0.5)

    # Test 2: Change STUN port (same IP, different port)
    response2, _, _ = send_tcp_stun_request(stun_host, stun_port + 1, source_ip)
    mapped2 = get_mapped_address(response2)

    if mapped1:
        if mapped1 == (source_ip, source_port1):
            print("TCP Mapping behavior: Direct")
        elif mapped2 and mapped1 == mapped2:
            print("TCP Mapping behavior: Endpoint-Independent")
        elif mapped2:
            # Test 3: Change source port (automatically done by send_tcp_stun_request)
            time.sleep(0.5)
            response3, _, _ = send_tcp_stun_request(stun_host, stun_port, source_ip)
            mapped3 = get_mapped_address(response3)
            if mapped3 and mapped3 == mapped2:
                print("TCP Mapping behavior: Address-Dependent")
            else:
                print("TCP Mapping behavior: Address and Port-Dependent")
        else:
            print("TCP Mapping behavior: Unknown (test 2 failed)")
    else:
        print("Failed to determine TCP Mapping behavior")

def run_tests(stun_host, stun_port, ip_version, interface_ip=None):
    """Run tests for a specific IP version"""
    print(f"\n{'=' * 50}")
    print(f"Testing {'IPv6' if ip_version == 6 else 'IPv4'} TCP")
    print(f"{'=' * 50}")
    
    external_ip, external_port, source_ip, _, other_address = test_stun(
        stun_host, stun_port, use_ipv6=(ip_version == 6), interface_ip=interface_ip
    )

    if external_ip and external_port:
        tcp_mapping_behavior(stun_host, stun_port, source_ip)
        return True
    return False

def main():
    # Get STUN server from command line argument if provided
    if len(sys.argv) > 1:
        stun_host = sys.argv[1]
        print(f"Using STUN server: {stun_host}")
    else:
        stun_host = input("STUN server host: ")
    
    # Check for flags
    skip_ipv4 = '--skip-ipv4' in sys.argv
    skip_ipv6 = '--skip-ipv6' in sys.argv
    
    # Get interface IPs if specified
    interface_ipv4 = None
    interface_ipv6 = None
    if '--interface-ipv4' in sys.argv:
        try:
            interface_idx = sys.argv.index('--interface-ipv4')
            if interface_idx + 1 < len(sys.argv):
                interface_ipv4 = sys.argv[interface_idx + 1]
        except (ValueError, IndexError):
            pass
    
    if '--interface-ipv6' in sys.argv:
        try:
            interface_idx = sys.argv.index('--interface-ipv6')
            if interface_idx + 1 < len(sys.argv):
                interface_ipv6 = sys.argv[interface_idx + 1]
        except (ValueError, IndexError):
            pass
    
    if interface_ipv4 or interface_ipv6:
        print(f"Using interface: IPv4={interface_ipv4 or 'auto'}, IPv6={interface_ipv6 or 'auto'}")
    
    # Get port from command line or use default
    port_arg_index = 2
    if len(sys.argv) > port_arg_index and sys.argv[port_arg_index] not in ['--skip-ipv4', '--skip-ipv6', '--interface-ipv4', '--interface-ipv6']:
        try:
            stun_port = int(sys.argv[port_arg_index])
            print(f"Using port: {stun_port}")
        except ValueError:
            stun_port = 3478
            print(f"Invalid port specified, using default: {stun_port}")
    else:
        # Only ask for port if it wasn't provided via command line
        stun_port = 3478
        print(f"Using default port: {stun_port}")
    
    # Run IPv4 tests if not skipped
    if not skip_ipv4:
        ipv4_success = run_tests(stun_host, stun_port, 4, interface_ipv4)
    
    # Run IPv6 tests if not skipped
    if not skip_ipv6:
        try:
            ipv6_success = run_tests(stun_host, stun_port, 6, interface_ipv6)
            if not ipv6_success:
                print("The STUN server may not support IPv6 TCP or IPv6 connectivity issues occurred.")
        except Exception:
            print("The STUN server may not support IPv6 TCP or IPv6 connectivity issues occurred.")


if __name__ == "__main__":
    main()
