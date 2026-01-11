"""
RFC 5780 NAT Behavior Discovery - TCP Implementation
Uses STUN protocol to determine NAT mapping behavior over TCP.
"""

import socket
import random
import time
import sys

from stun_utils import (
    build_binding_request, parse_stun_response,
    get_mapped_address, check_ipv6_connectivity, get_source_ip
)


def send_tcp_stun_request(stun_host, stun_port, source_ip, timeout=5, retries=5, use_backoff=True):
    """Send TCP STUN request with exponential backoff retry logic"""
    sock = None
    base_delay = 0.5
    
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
                delay = base_delay * (2 ** attempt)
                time.sleep(min(delay, 8))
    return None, None, None


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


def tcp_mapping_behavior(stun_host, stun_port, source_ip):
    """Determine TCP NAT mapping behavior per RFC 5780"""
    response1, _, source_port1 = send_tcp_stun_request(stun_host, stun_port, source_ip)
    mapped1 = get_mapped_address(response1)
    time.sleep(0.5)

    response2, _, _ = send_tcp_stun_request(stun_host, stun_port + 1, source_ip)
    mapped2 = get_mapped_address(response2)

    if mapped1:
        if mapped1 == (source_ip, source_port1):
            print("TCP Mapping behavior: Direct")
        elif mapped2 and mapped1 == mapped2:
            print("TCP Mapping behavior: Endpoint-Independent")
        elif mapped2:
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
