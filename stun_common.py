import socket
import struct
import random

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

def print_binding_result(response, source_ip, source_port):
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
        print("Binding status: Failed")
    return response
