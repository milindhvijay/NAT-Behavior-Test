"""
RFC 5780 NAT Behavior Discovery - UDP Implementation
Uses STUN protocol to determine NAT mapping and filtering behavior over UDP.
"""

import socket
import random
import struct
import time
import sys

from stun_utils import (
    MAGIC_COOKIE, BINDING_REQUEST, ATTR_CHANGE_REQUEST,
    build_binding_request, parse_stun_response,
    get_mapped_address, check_ipv6_connectivity, get_source_ip
)


def send_stun_request(stun_host, stun_port, source_ip, source_port, retries=3, timeout=5, use_backoff=True):
    """Send STUN request with exponential backoff retry logic"""
    sock = None
    base_delay = 0.5
    
    for attempt in range(retries):
        try:
            sock = socket.socket(socket.AF_INET6 if ':' in source_ip else socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            try:
                sock.bind((source_ip, source_port))
            except OSError:
                sock.close()
                continue
            message = build_binding_request()
            sock.sendto(message, (stun_host, stun_port))
            response, _ = sock.recvfrom(2048)
            parsed_response = parse_stun_response(response)
            sock.close()
            return parsed_response, source_ip, source_port
        except socket.timeout:
            if sock:
                sock.close()
            if use_backoff:
                delay = base_delay * (2 ** attempt)
                time.sleep(min(delay, 8))
            else:
                time.sleep(1)
        except Exception:
            if sock:
                sock.close()
            if use_backoff:
                delay = base_delay * (2 ** attempt)
                time.sleep(min(delay, 8))
            else:
                time.sleep(1)
    return None, None, None


def test_stun(server, port, use_ipv6=False, interface_ip=None):
    """Test STUN binding and return external address information"""
    source_ip = get_source_ip(use_ipv6, interface_ip)
    if not source_ip:
        return None, None, None, None, None
        
    source_port = random.randint(49152, 65535)
    response, source_ip, source_port = send_stun_request(server, port, source_ip, source_port)

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


def mapping_behavior(stun_host, stun_port, source_ip, source_port):
    """Determine NAT mapping behavior per RFC 5780"""
    response1, _, _ = send_stun_request(stun_host, stun_port, source_ip, source_port)
    mapped1 = get_mapped_address(response1)
    time.sleep(0.5)
    
    response2, _, _ = send_stun_request(stun_host, stun_port + 1, source_ip, source_port)
    mapped2 = get_mapped_address(response2)

    if mapped1:
        if mapped1 == (source_ip, source_port):
            print("Mapping behavior: Direct")
        elif mapped2 and mapped1 == mapped2:
            print("Mapping behavior: Endpoint-Independent")
        elif mapped2 and mapped1 != mapped2:
            time.sleep(0.5)
            response3, _, _ = send_stun_request(stun_host, stun_port, source_ip, source_port + 1)
            mapped3 = get_mapped_address(response3)
            if mapped3 and mapped3 == mapped2:
                print("Mapping behavior: Address-Dependent")
            else:
                print("Mapping behavior: Address and Port-Dependent")
        else:
            print("Mapping behavior: Unknown (test 2 failed)")
    else:
        print("Failed to determine Mapping behavior")


def filtering_behavior(stun_host, stun_port, source_ip, source_port):
    """Determine NAT filtering behavior per RFC 5780"""
    sock = socket.socket(socket.AF_INET6 if ':' in source_ip else socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((source_ip, source_port))
    sock.settimeout(5)

    def send_change_request(change_ip, change_port):
        transaction_id = random.randbytes(12)
        message_type = struct.pack('!H', BINDING_REQUEST)
        message_length = struct.pack('!H', 8)
        magic_cookie = struct.pack('!I', MAGIC_COOKIE)
        change_request_value = (change_ip << 2) | (change_port << 1)
        change_request = struct.pack('!HHI', ATTR_CHANGE_REQUEST, 4, change_request_value)
        message = message_type + message_length + magic_cookie + transaction_id + change_request

        try:
            sock.sendto(message, (stun_host, stun_port))
            response, _ = sock.recvfrom(2048)
            return True
        except socket.timeout:
            return False

    try:
        if send_change_request(True, True):
            print("Filtering behavior: Endpoint-Independent")
            return

        if send_change_request(True, False):
            print("Filtering behavior: Address-Dependent")
        else:
            print("Filtering behavior: Address and Port-Dependent")
    finally:
        sock.close()


def run_tests(stun_host, stun_port, ip_version, interface_ip=None):
    """Run tests for a specific IP version"""
    print(f"\n{'=' * 50}")
    print(f"Testing {'IPv6' if ip_version == 6 else 'IPv4'}")
    print(f"{'=' * 50}")
    
    external_ip, external_port, source_ip, source_port, other_address = test_stun(
        stun_host, stun_port, use_ipv6=(ip_version == 6), interface_ip=interface_ip
    )

    if external_ip and external_port:
        mapping_behavior(stun_host, stun_port, source_ip, source_port)
        filtering_behavior(stun_host, stun_port, source_ip, source_port)
        return True
    return False


def main():
    if len(sys.argv) > 1:
        stun_host = sys.argv[1]
        print(f"Using STUN server: {stun_host}")
    else:
        stun_host = input("STUN server host: ")
    
    skip_ipv4 = '--skip-ipv4' in sys.argv
    skip_ipv6 = '--skip-ipv6' in sys.argv
    
    interface_ipv4 = None
    interface_ipv6 = None
    if '--interface-ipv4' in sys.argv:
        try:
            idx = sys.argv.index('--interface-ipv4')
            if idx + 1 < len(sys.argv):
                interface_ipv4 = sys.argv[idx + 1]
        except (ValueError, IndexError):
            pass
    
    if '--interface-ipv6' in sys.argv:
        try:
            idx = sys.argv.index('--interface-ipv6')
            if idx + 1 < len(sys.argv):
                interface_ipv6 = sys.argv[idx + 1]
        except (ValueError, IndexError):
            pass
    
    stun_port = 3478
    for i, arg in enumerate(sys.argv):
        if arg.isdigit() and i > 1:
            stun_port = int(arg)
            break
    
    print(f"Using default port: {stun_port}")
    
    if not skip_ipv4:
        run_tests(stun_host, stun_port, 4, interface_ipv4)
    
    if not skip_ipv6:
        if check_ipv6_connectivity():
            run_tests(stun_host, stun_port, 6, interface_ipv6)
        else:
            print("\nIPv6: Not available")


if __name__ == "__main__":
    main()
