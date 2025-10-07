import socket
import random
import struct
import time
import sys

#Constants for STUN Message
MAGIC_COOKIE = 0x2112A442
BINDING_REQUEST = 0x0001

def build_binding_request():
    #Generate a random 96-bit transaction ID
    transaction_id = random.randbytes(12)
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
    except Exception:
        return None

def send_stun_request(stun_host, stun_port, source_ip, source_port, retries=3, timeout=5):
    sock = None
    for attempt in range(retries):
        try:
            #Create a UDP socket
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
            mapped_address =  parse_stun_response(response)
            sock.close()
            return mapped_address, source_ip, source_port
        except socket.timeout:
            if sock:
                sock.close()
            time.sleep(1)
        except Exception:
            if sock:
                sock.close()
            time.sleep(1)
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
        
    source_port = random.randint(49152, 65535)
    response, source_ip, source_port = send_stun_request(server, port, source_ip, source_port)

    if response:
        external_ip, external_port = response
        if ':' in (source_ip or ''):
            print(f"Internal: [{source_ip}]:{source_port}")
            print(f"External: [{external_ip}]:{external_port}")
        else:
            print(f"Internal: {source_ip}:{source_port}")
            print(f"External: {external_ip}:{external_port}")
    else:
        external_ip, external_port = None, None
        print(f"Failed to get STUN response")

    return external_ip, external_port, source_ip, source_port

def mapping_behavior(stun_host, stun_port, source_ip, source_port):
    #Test 1: Send to primary STUN server
    response1 = send_stun_request(stun_host, stun_port, source_ip, source_port)
    time.sleep(1)
    #Test 2: Change STUN port
    response2 = send_stun_request(stun_host, stun_port + 1, source_ip, source_port)

    if response1:
        if (response1[0] == (source_ip, source_port)):
            print("Mapping behavior: Direct")
        elif (response1[0] == response2[0]):
            print("Mapping behavior: Endpoint-Independent")
        elif (response1[0] != response2[0]):
            #Test 3: Change source port
            response3 = send_stun_request(stun_host, stun_port, source_ip, source_port + 1)
            if (response3[0] == response2[0]):
                print("Mapping behavior: Address-Dependent")
            else:
                print("Mapping behavior: Address and Port-Dependent")
    else:
        print("Failed to determine Mapping behavior")

def filtering_behavior(stun_host, stun_port, source_ip, source_port):
    sock = socket.socket(socket.AF_INET6 if ':' in source_ip else socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((source_ip, source_port))
    sock.settimeout(5)

    def send_change_request(change_ip, change_port):
        #Sends STUN request with CHANGE-REQUEST attribute
        transaction_id = random.randbytes(12)
        message_type = struct.pack('!H', BINDING_REQUEST)
        message_length = struct.pack('!H', 8)
        magic_cookie = struct.pack('!I', MAGIC_COOKIE)
        change_request_value = (change_ip << 2) | (change_port << 1)
        change_request = struct.pack('!HHI', 0x0003, 4, change_request_value)

        message = message_type + message_length + magic_cookie + transaction_id + change_request

        try:
            sock.sendto(message, (stun_host, stun_port))
            response, _ = sock.recvfrom(2048)
            return True
        except socket.timeout:
            return False

    try:
        #Test 1: Change both IP and port
        response1 = send_change_request(True, True)
        if response1:
            print("Fitering behavior: Endpoint-Independent")
            return

        #Test 2: Change IP only
        response2 = send_change_request(True, False)
        if response2:
            print("Filtering behavior: Address-Dependent")
        else:
            print("Filtering behavior: Address and Port-Dependent")
    finally:
        sock.close()

def run_tests(stun_host, stun_port, ip_version):
    """Run tests for a specific IP version"""
    print(f"\n{'=' * 50}")
    print(f"Testing {'IPv6' if ip_version == 6 else 'IPv4'}")
    print(f"{'=' * 50}")
    
    external_ip, external_port, source_ip, source_port = test_stun(
        stun_host, stun_port, use_ipv6=(ip_version == 6)
    )

    if external_ip and external_port:
        mapping_behavior(stun_host, stun_port, source_ip, source_port)
        filtering_behavior(stun_host, stun_port, source_ip, source_port)
        return True
    return False

def main():
    # Get STUN server from command line argument if provided
    if len(sys.argv) > 1:
        stun_host = sys.argv[1]
        print(f"Using STUN server: {stun_host}")
    else:
        stun_host = input("STUN server host: ")
    
    # Check for skip-ipv6 flag
    skip_ipv6 = '--skip-ipv6' in sys.argv
    
    # Get port from command line or use default
    port_arg_index = 2
    if len(sys.argv) > port_arg_index and sys.argv[port_arg_index] != '--skip-ipv6':
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
    
    # Always run IPv4 tests
    ipv4_success = run_tests(stun_host, stun_port, 4)
    
    # Run IPv6 tests only if not skipped
    if not skip_ipv6:
        try:
            ipv6_success = run_tests(stun_host, stun_port, 6)
            if not ipv6_success:
                print("The STUN server may not support IPv6 or IPv6 connectivity issues occurred.")
        except Exception:
            print("The STUN server may not support IPv6 or IPv6 connectivity issues occurred.")


if __name__ == "__main__":
    main()
