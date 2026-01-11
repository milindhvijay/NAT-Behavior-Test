"""
STUN Protocol Utilities
Shared constants and parsing functions for RFC 5780/5389/8489 STUN protocol.
"""

import socket
import struct
import random

# Constants for STUN Message
MAGIC_COOKIE = 0x2112A442
BINDING_REQUEST = 0x0001
BINDING_SUCCESS_RESPONSE = 0x0101

# STUN Attribute Types
ATTR_MAPPED_ADDRESS = 0x0001
ATTR_RESPONSE_ADDRESS = 0x0002
ATTR_CHANGE_REQUEST = 0x0003
ATTR_SOURCE_ADDRESS = 0x0004
ATTR_CHANGED_ADDRESS = 0x0005
ATTR_XOR_MAPPED_ADDRESS = 0x0020
ATTR_SOFTWARE = 0x8022
ATTR_RESPONSE_ORIGIN = 0x802B
ATTR_OTHER_ADDRESS = 0x802C


def build_binding_request():
    """Generate a STUN Binding Request with random transaction ID"""
    transaction_id = random.randbytes(12)
    message_type = struct.pack('!H', BINDING_REQUEST)
    message_length = struct.pack('!H', 0)  # No attributes, thus length is 0
    magic_cookie = struct.pack('!I', MAGIC_COOKIE)
    return message_type + message_length + magic_cookie + transaction_id


def parse_stun_response(response):
    """
    Parse STUN response and extract mapped address.
    Supports both MAPPED-ADDRESS and XOR-MAPPED-ADDRESS (preferred).
    Also extracts OTHER-ADDRESS and RESPONSE-ORIGIN if present.
    
    Returns dict with 'address', 'other_address', 'response_origin', 'software'
    or None if parsing fails.
    """
    if len(response) < 20:
        return None

    try:
        message_type, message_length, magic = struct.unpack('!HHI', response[:8])
        transaction_id = response[8:20]
        attributes = response[20:]

        # Check for Binding Success Response
        if message_type != BINDING_SUCCESS_RESPONSE:
            return None

        result = {
            'mapped_address': None,
            'xor_mapped_address': None,
            'other_address': None,
            'response_origin': None,
            'software': None
        }

        i = 0
        while i < len(attributes):
            if i + 4 > len(attributes):
                break
            attribute_type, attribute_length = struct.unpack('!HH', attributes[i:i+4])
            i += 4
            if i + attribute_length > len(attributes):
                break

            attr_data = attributes[i:i+attribute_length]

            if attribute_type == ATTR_MAPPED_ADDRESS:
                result['mapped_address'] = parse_address_attribute(attr_data)
            
            elif attribute_type == ATTR_XOR_MAPPED_ADDRESS:
                result['xor_mapped_address'] = parse_xor_address_attribute(attr_data, transaction_id)
            
            elif attribute_type == ATTR_OTHER_ADDRESS:
                result['other_address'] = parse_xor_address_attribute(attr_data, transaction_id)
            
            elif attribute_type == ATTR_RESPONSE_ORIGIN:
                result['response_origin'] = parse_xor_address_attribute(attr_data, transaction_id)
            
            elif attribute_type == ATTR_SOFTWARE:
                try:
                    result['software'] = attr_data.decode('utf-8').rstrip('\x00')
                except:
                    pass

            # Move to next attribute (with padding to 4-byte boundary)
            i += attribute_length
            if attribute_length % 4 != 0:
                i += 4 - (attribute_length % 4)

        # Prefer XOR-MAPPED-ADDRESS over MAPPED-ADDRESS (RFC 5389 recommendation)
        mapped = result['xor_mapped_address'] or result['mapped_address']
        
        if mapped:
            return {
                'address': mapped,
                'other_address': result['other_address'],
                'response_origin': result['response_origin'],
                'software': result['software']
            }
        return None

    except Exception:
        return None


def parse_address_attribute(attr_data):
    """Parse MAPPED-ADDRESS attribute (non-XORed)"""
    if len(attr_data) < 8:
        return None
    
    family = struct.unpack('!B', attr_data[1:2])[0]
    port = struct.unpack('!H', attr_data[2:4])[0]
    
    if family == 0x01:  # IPv4
        ip = socket.inet_ntoa(attr_data[4:8])
        return (ip, port)
    elif family == 0x02 and len(attr_data) >= 20:  # IPv6
        ip = socket.inet_ntop(socket.AF_INET6, attr_data[4:20])
        return (ip, port)
    return None


def parse_xor_address_attribute(attr_data, transaction_id):
    """Parse XOR-MAPPED-ADDRESS attribute (XORed with magic cookie)"""
    if len(attr_data) < 8:
        return None
    
    family = struct.unpack('!B', attr_data[1:2])[0]
    xored_port = struct.unpack('!H', attr_data[2:4])[0]
    
    # XOR port with upper 16 bits of magic cookie
    port = xored_port ^ (MAGIC_COOKIE >> 16)
    
    if family == 0x01:  # IPv4
        xored_ip = attr_data[4:8]
        magic_bytes = struct.pack('!I', MAGIC_COOKIE)
        ip_bytes = bytes(a ^ b for a, b in zip(xored_ip, magic_bytes))
        ip = socket.inet_ntoa(ip_bytes)
        return (ip, port)
    elif family == 0x02 and len(attr_data) >= 20:  # IPv6
        xored_ip = attr_data[4:20]
        magic_bytes = struct.pack('!I', MAGIC_COOKIE) + transaction_id
        ip_bytes = bytes(a ^ b for a, b in zip(xored_ip, magic_bytes))
        ip = socket.inet_ntop(socket.AF_INET6, ip_bytes)
        return (ip, port)
    return None


def get_mapped_address(response):
    """Extract mapped address from response (handles both old and new format)"""
    if response is None:
        return None
    if isinstance(response, dict):
        return response.get('address')
    return response


def check_ipv6_connectivity():
    """Check if the host can access IPv6 sites"""
    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        sock.settimeout(2)
        sock.connect(("2001:4860:4860::8888", 80))
        sock.close()
        return True
    except Exception:
        return False


def get_source_ip(use_ipv6=False, interface_ip=None):
    """Get the source IP address for outgoing connections"""
    if interface_ip:
        return interface_ip
    
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
