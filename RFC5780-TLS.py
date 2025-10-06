import socket
import struct
import random
import time
import ssl
import sys
import concurrent.futures

#Constants for STUN Message
MAGIC_COOKIE = 0x2112A442
BINDING_REQUEST = 0x0001

def build_binding_request():
    #Generate a random 96-bit transaction ID
    transaction_id = b''.join(struct.pack('!B', random.randint(0, 255)) for _ in range(12))
    message_type = struct.pack('!H', BINDING_REQUEST)
    message_length = struct.pack('!H', 0) #No attributes, thus length is 0
    magic_cookie = struct.pack('!I', MAGIC_COOKIE)
    return message_type + message_length + magic_cookie + transaction_id

def parse_stun_response(response):
    #To parse the STUN response to extract the mapped address
    if len(response) < 20:
        return None

    try:
        message_type, message_length, _ = struct.unpack('!HHI', response[:8])
        attributes = response[20:]

        if message_type != 0x0101:
            return None

        i = 0
        while i < len(attributes):
            if i + 4 > len(attributes):
                break
            attribute_type, attribute_length = struct.unpack('!HH', attributes[i:i+4])
            i += 4
            if i + attribute_length > len(attributes):
                break
            if attribute_type == 0x0001: #Mapped Address attribute
                if attribute_length >= 8:
                    family = struct.unpack('!B', attributes[i+1:i+2])[0]
                    port = struct.unpack('!H', attributes[i+2:i+4])[0]
                    if family == 0x01 and attribute_length >= 8: #IPv4
                        ip = socket.inet_ntoa(attributes[i+4:i+8])
                        return (ip, port)
                    elif family == 0x02 and attribute_length >= 20: #IPv6
                        ip = socket.inet_ntop(socket.AF_INET6, attributes[i+4:i+20])
                        return (ip, port)
            i += attribute_length
        return None
    except Exception as e:
        print(f"Error parsing STUN response: {e}")
        return None

def send_tls_stun_request(stun_host, stun_port, source_ip, timeout=5):
    for _ in range(5):
        try:
            source_port = random.randint(49152, 65535)
            sock = socket.socket(socket.AF_INET6 if ':' in source_ip else socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.bind((source_ip, source_port))

            #Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            #Wrap the socket with SSL
            secure_sock = context.wrap_socket(sock, server_hostname=stun_host)
            secure_sock.connect((stun_host, stun_port))

            message = build_binding_request()
            secure_sock.sendall(message)

            response = secure_sock.recv(2048)
            mapped_address = parse_stun_response(response)
            return mapped_address, source_ip, source_port
        except (socket.error, ssl.SSLError) as e:
            print(f"Error sending TLS STUN request (retrying): {e}")
        finally:
            try:
                secure_sock.close()
            except:
                pass
            sock.close()
    print("Failed to send TLS STUN request after multiple attempts")
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

def get_source_ip(use_ipv6=False):
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

def test_stun(server, port, use_ipv6=False):
    source_ip = get_source_ip(use_ipv6)
    if not source_ip:
        return None, None, None, None
        
    response, source_ip, source_port = send_tls_stun_request(server, port, source_ip)

    if response:
        external_ip, external_port = response
        print(f"{'IPv6' if use_ipv6 else 'IPv4'} Binding status: Success")
        if ':' in (source_ip or ''):
            print(f"Internal: [{source_ip}]:{source_port}")
            print(f"External: [{external_ip}]:{external_port}")
        else:
            print(f"Internal: {source_ip}:{source_port}")
            print(f"External: {external_ip}:{external_port}")
    else:
        external_ip, external_port = None, None
        print(f"{'IPv6' if use_ipv6 else 'IPv4'} Binding status: Failed")

    return external_ip, external_port, source_ip, source_port

def tls_mapping_behavior(stun_host, stun_port, source_ip):
    #Test 1: Send to primary STUN server
    response1 = send_tls_stun_request(stun_host, stun_port, source_ip)
    time.sleep(1)

    #Test 2: Change STUN port
    response2 = send_tls_stun_request(stun_host, stun_port + 1, source_ip)

    if response1[0]:
        if response1[0] == (source_ip, response1[2]):
            print("TLS Mapping behavior: Direct")
        elif response1[0] == response2[0]:
            print("TLS Mapping behavior: Endpoint-Independent")
        else:
            #Test 3: Change source port (automatically done by send_tls_stun_request)
            response3 = send_tls_stun_request(stun_host, stun_port, source_ip)
            if response3[0] == response2[0]:
                print("TLS Mapping behavior: Address-Dependent")
            else:
                print("TLS Mapping behavior: Address and Port-Dependent")
    else:
        print("Failed to determine TLS Mapping behavior")

def run_tests(stun_host, stun_port, ip_version):
    """Run tests for a specific IP version"""
    print(f"\n{'=' * 50}")
    print(f"Testing {'IPv6' if ip_version == 6 else 'IPv4'} TLS")
    print(f"{'=' * 50}")
    
    external_ip, external_port, source_ip, _ = test_stun(
        stun_host, stun_port, use_ipv6=(ip_version == 6)
    )

    if external_ip and external_port:
        tls_mapping_behavior(stun_host, stun_port, source_ip)
        return True
    return False

def main():
    # Get STUN server from command line argument if provided
    if len(sys.argv) > 1:
        stun_host = sys.argv[1]
        print(f"Using STUN server: {stun_host}")
    else:
        stun_host = input("STUN server host (must support TLS): ")
    
    # Get port from command line or use default
    if len(sys.argv) > 2:
        try:
            stun_port = int(sys.argv[2])
            print(f"Using port: {stun_port}")
        except ValueError:
            stun_port = 5349
            print(f"Invalid port specified, using default: {stun_port}")
    else:
        # Only ask for port if it wasn't provided via command line
        stun_port = 5349
        print(f"Using default port: {stun_port}")
    
    # Automatically check IPv6 connectivity
    has_ipv6 = check_ipv6_connectivity()
    
    # Always run IPv4 tests
    ipv4_success = run_tests(stun_host, stun_port, 4)
    
    # Run IPv6 tests only if connectivity is available
    if has_ipv6:
        try:
            ipv6_success = run_tests(stun_host, stun_port, 6)
            if not ipv6_success:
                print("The STUN server may not support IPv6 TLS or IPv6 connectivity issues occurred.")
        except Exception as e:
            print(f"\nError during IPv6 TLS testing: {e}")
            print("The STUN server may not support IPv6 TLS.")
    else:
        print("\nNo IPv6 connectivity detected. Skipping IPv6 tests.")


if __name__ == "__main__":
    main()
