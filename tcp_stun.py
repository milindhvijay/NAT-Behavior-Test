import socket
import time
import random
from stun_common import build_binding_request, parse_stun_response, get_source_ip, print_binding_result

def send_tcp_stun_request(stun_host, stun_port, source_ip, timeout=5):
    for _ in range(5):
        try:
            source_port = random.randint(49152, 65535)
            sock = socket.socket(socket.AF_INET6 if ':' in source_ip else socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.bind((source_ip, source_port))
            sock.connect((stun_host, stun_port))

            message = build_binding_request()
            sock.sendall(message)

            response = sock.recv(2048)
            mapped_address = parse_stun_response(response)
            return mapped_address, source_ip, source_port
        except socket.error as e:
            print(f"Error sending TCP STUN request (retrying): {e}")
        finally:
            sock.close()
    print("Failed to send TCP STUN request after multiple attempts")
    return None, None, None

def test_stun(server, port, use_ipv6=False):
    source_ip = get_source_ip(use_ipv6)
    response, source_ip, source_port = send_tcp_stun_request(server, port, source_ip)
    return print_binding_result(response, source_ip, source_port)

def tcp_mapping_behavior(stun_host, stun_port, source_ip):
    #Test 1: Send to primary STUN server
    response1 = send_tcp_stun_request(stun_host, stun_port, source_ip)
    time.sleep(1)

    #Test 2: Change STUN port
    response2 = send_tcp_stun_request(stun_host, stun_port + 1, source_ip)

    if response1[0]:
        if response1[0] == (source_ip, response1[2]):
            print("TCP Mapping behavior: Direct")
        elif response1[0] == response2[0]:
            print("TCP Mapping behavior: Endpoint-Independent")
        else:
            #Test 3: Change source port (automatically done by send_tcp_stun_request)
            response3 = send_tcp_stun_request(stun_host, stun_port, source_ip)
            if response3[0] == response2[0]:
                print("TCP Mapping behavior: Address-Dependent")
            else:
                print("TCP Mapping behavior: Address and Port-Dependent")
    else:
        print("Failed to determine TCP Mapping behavior")

def main():
    stun_host = input("STUN server host (must support TCP): ")
    stun_port_input = input("STUN server port (default is 3478): ")
    use_ipv6_input = input("Use IPv6? (yes/no): ").strip().lower() == 'yes'

    stun_port = int(stun_port_input) if stun_port_input else 3478

    result = test_stun(stun_host, stun_port, use_ipv6=use_ipv6_input)
    if result:
        external_ip, external_port = result
        source_ip = get_source_ip(use_ipv6_input)
        tcp_mapping_behavior(stun_host, stun_port, source_ip)

if __name__ == "__main__":
    main()
