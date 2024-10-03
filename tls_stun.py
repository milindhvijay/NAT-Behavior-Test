import socket
import time
import random
import ssl
from stun_common import build_binding_request, parse_stun_response, get_source_ip, print_binding_result

def send_tls_stun_request(stun_host, stun_port, source_ip, timeout=5):
    for _ in range(5):
        try:
            source_port = random.randint(49152, 65535)
            sock = socket.socket(socket.AF_INET6 if ':' in source_ip else socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.bind((source_ip, source_port))

            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

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

def test_stun(server, port, use_ipv6=False):
    source_ip = get_source_ip(use_ipv6)
    response, source_ip, source_port = send_tls_stun_request(server, port, source_ip)
    return print_binding_result(response, source_ip, source_port)

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

def main():
    stun_host = input("STUN server host (must support TLS): ")
    stun_port_input = input("STUN server port (default is 5349 for TLS): ")
    use_ipv6_input = input("Use IPv6? (yes/no): ").strip().lower() == 'yes'

    stun_port = int(stun_port_input) if stun_port_input else 5349

    result = test_stun(stun_host, stun_port, use_ipv6=use_ipv6_input)
    if result:
        external_ip, external_port = result
        source_ip = get_source_ip(use_ipv6_input)
        tls_mapping_behavior(stun_host, stun_port, source_ip)

if __name__ == "__main__":
    main()
