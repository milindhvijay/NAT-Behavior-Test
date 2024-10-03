import socket
import struct
import random
import time
import ssl
from dtls import do_patch

#Patch SSL to support DTLS
do_patch()

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
        print(f"Error getting source IP: {e}")
        return None

def send_dtls_stun_request(stun_host, stun_port, source_ip, timeout=5):
    for _ in range(5): #Try up to 5 times
        try:
            source_port = random.randint(49152, 65535)
            sock = socket.socket(socket.AF_INET6 if ':' in source_ip else socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.bind((source_ip, source_port))

            #Create SSL context for DTLS
            context = ssl.create_default_context()
            context.verify_mode = ssl.CERT_NONE
            context.check_hostname = False
            context.set_ciphers('ALL')

            #Wrapt the UDP socket to create a DTLS socket
            with context.wrap_socket(sock, server_hostname=stun_host, do_handshake_on_connect=True) as dtls_sock:
                dtls_sock.connect((stun_host, stun_port))

                message = build_binding_request()
                dtls_sock.send(message)

                response = dtls_sock.recv(2048)
                mapped_address = parse_stun_response(response)
                return mapped_address, source_ip, source_port
        except Exception as e:
            print(f"Error sending DTLS STUN request (retrying): {e}")
        finally:
            sock.close()
    print("Failed to send DTLS STUN request")
    return None, None, None

def test_stun(server, port, use_ipv6=False):
    source_ip = get_source_ip(use_ipv6)
    response, source_ip, source_port = send_dtls_stun_request(server, port, source_ip)

    if response:
        external_ip, external_port = response
        print("Binding status: Success")
        if ':' in (source_ip or ''):
            print(f"Internal: [{source_ip}]:{source_port}")
            print(f"External: [{external_ip}]:{external_port}")
        else:
            print(f"Internal: {source_ip}:{source_port}")
            print(f"External: {external_ip}:{external_port}")
    else:
        external_ip, external_port = None, None
        print("Binding status: Failed")

    return external_ip, external_port, source_ip, source_port

def dtls_mapping_behavior(stun_host, stun_port, source_ip, source_port):
    #Test 1: Send to primary STUN server
    response1 = send_dtls_stun_request(stun_host, stun_port, source_ip)
    time.sleep(1)

    #Test 2: Change STUN port
    response2 = send_dtls_stun_request(stun_host, stun_port + 1, source_ip)

    if response1[0]:
        if response1[0] == (source_ip, source_port):
            print("DTLS Mapping behavior: Direct")
        elif response1[0] == response2[0]:
            print("DTLS Mapping behavior: Endpoint-Independent")
        else:
            #Test 3: Change source port (automatically done by send_dtls_stun_request)
            response3 = send_dtls_stun_request(stun_host, stun_port, source_ip)
            if response3[0] == response2[0]:
                print("DTLS Mapping behavior: Address-Dependent")
            else:
                print("DTLS Mapping behavior: Address and Port-Dependent")
    else:
        print("Failed to determine DTLS Mapping behavior")

def main():
    stun_host = input("STUN server host (must support DTLS): ")
    stun_port_input = input("STUN server port (default is 5349 for DTLS): ")
    use_ipv6_input = input("Use IPv6? (yes/no): ").strip().lower() == 'yes'

    stun_port = int(stun_port_input) if stun_port_input else 5349

    external_ip, external_port, source_ip, source_port = test_stun(stun_host, stun_port, use_ipv6=use_ipv6_input)

    if external_ip and external_port:
        dtls_mapping_behavior(stun_host, stun_port, source_ip, source_port)

if __name__ == "__main__":
    main()
