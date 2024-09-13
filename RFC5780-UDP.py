from os import execlpe
import socket
import random
import struct
import time

# Constants for STUN Message
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
        message_type, message_length, _ = struct.pack('!HHI', response[:8])
        attributes = response[20:]

        if message_length != 0x0101:
            return None

        i = 0
        while i < len(attributes):
            if i + 4 > len(attributes):
                break
            attribute_type, attribute_length = struct.pack('!HH', attributes[i:i+4])
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
    for attempt in range(retries):
        try:
            #Create a UDP socket
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
            mapped_address =  parse_stun_response(response)
            return mapped_address, source_ip, source_port
        except socket.timeout:
            print(f"Socket timed out on attempt {attempt + 1}/{retries} from port {source_port}")
        except Exception as e:
            print(f"Error sending STUN request: {e}")
        finally:
            sock.close()
            time.sleep(1)
    return None, None, None

def get_source_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        source_ip = s.getsockname()[0]
        s.close()
        return source_ip
    except Exception as e:
        print(f"Error getting source IP: {e}")
        return None

def get_source_ipv6():
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s.connect(("2001:4860:4860::8888", 80))
        source_ip = s.getpeername()[0]
        s.close()
        return source_ip
    except Exception as e:
        print(f"Error getting source IPv6: {e}")
        return None
