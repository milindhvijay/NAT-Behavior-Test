import socket
import struct
import time
import random
from stun_common import build_binding_request, parse_stun_response, get_source_ip, print_binding_result

#Constants for STUN Message
MAGIC_COOKIE = 0x2112A442
BINDING_REQUEST = 0x0001

def send_stun_request(stun_host, stun_port, source_ip, source_port, retries=3, timeout=5):
    for attempt in range(retries):
        try:
            sock = socket.socket(socket.AF_INET6 if ':' in source_ip else socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            try:
                sock.bind((source_ip, source_port))
            except OSError as e:
                print(f"Error binding to port {source_port}: {e}")
                continue
            message = build_binding_request()
            sock.sendto(message, (stun_host, stun_port))
            response, _ = sock.recvfrom(2048)
            mapped_address = parse_stun_response(response)
            return mapped_address, source_ip, source_port
        except socket.timeout:
            print(f"Socket timed out on attempt {attempt + 1}/{retries} from port {source_port}")
        except Exception as e:
            print(f"Error sending STUN request: {e}")
        finally:
            sock.close()
        time.sleep(1)
    return None, None, None

def test_stun(server, port, use_ipv6=False):
    source_ip = get_source_ip(use_ipv6)
    source_port = random.randint(49152, 65535)
    response, source_ip, source_port = send_stun_request(server, port, source_ip, source_port)
    return print_binding_result(response, source_ip, source_port)

def mapping_behavior(stun_host, stun_port, source_ip, source_port):
    response1 = send_stun_request(stun_host, stun_port, source_ip, source_port)
    time.sleep(1)
    response2 = send_stun_request(stun_host, stun_port + 1, source_ip, source_port)

    if response1[0]:
        if (response1[0] == (source_ip, source_port)):
            print("Mapping behavior: Direct")
        elif (response1[0] == response2[0]):
            print("Mapping behavior: Endpoint-Independent")
        elif (response1[0] != response2[0]):
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
        transaction_id = b''.join(struct.pack('!B', random.randint(0,255)) for _ in range(12))
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
        response1 = send_change_request(True, True)
        if response1:
            print("Filtering behavior: Endpoint-Independent")
            return

        response2 = send_change_request(True, False)
        if response2:
            print("Filtering behavior: Address-Dependent")
        else:
            print("Filtering behavior: Address and Port-Dependent")
    finally:
        sock.close()

def main():
    stun_host = input("STUN server host: ")
    stun_port_input = input("STUN server port (default is 3478): ")
    use_ipv6_input = input("Use IPv6? (yes/no): ").strip().lower() == 'yes'

    stun_port = int(stun_port_input) if stun_port_input else 3478

    result = test_stun(stun_host, stun_port, use_ipv6=use_ipv6_input)
    if result:
        external_ip, external_port = result
        source_ip = get_source_ip(use_ipv6_input)
        source_port = random.randint(49152, 65535)
        mapping_behavior(stun_host, stun_port, source_ip, source_port)
        filtering_behavior(stun_host, stun_port, source_ip, source_port)

if __name__ == "__main__":
    main()
