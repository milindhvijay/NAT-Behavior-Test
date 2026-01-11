import os
import subprocess
import sys
import re
import socket
import platform

# Compile regex patterns once at module level for better performance
DOMAIN_PATTERN = re.compile(r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')
DOMAIN_PATTERN_NUMERIC_TLD = re.compile(r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z0-9]{2,}$')

# List of STUN servers to choose from
STUN_SERVERS = [
    "stun.hot-chilli.net",
    "stun.fitauto.ru",
    "stun.internetcalls.com",
    "stun.voip.aebc.com",
    "Custom Server",  # Option to enter a custom server
]

# Test configuration options
TEST_OPTIONS = {
    'protocols': {
        '1': {'name': 'All Protocols', 'tests': ['UDP', 'TCP', 'TLS']},
        '2': {'name': 'UDP only', 'tests': ['UDP']},
        '3': {'name': 'TCP only', 'tests': ['TCP']},
        '4': {'name': 'TLS only', 'tests': ['TLS']},
        '5': {'name': 'UDP + TCP', 'tests': ['UDP', 'TCP']},
        '6': {'name': 'UDP + TLS', 'tests': ['UDP', 'TLS']},
        '7': {'name': 'TCP + TLS', 'tests': ['TCP', 'TLS']},
    },
    'ip_versions': {
        '1': {'name': 'Both IPv4 and IPv6', 'skip_ipv4': False, 'skip_ipv6': False},
        '2': {'name': 'IPv4 only', 'skip_ipv4': False, 'skip_ipv6': True},
        '3': {'name': 'IPv6 only', 'skip_ipv4': True, 'skip_ipv6': False},
    }
}

def select_test_options(ipv4_available, ipv6_available):
    """
    Present test selection menu and return user's choices.
    Returns a dict with 'protocols' (list) and 'skip_ipv4', 'skip_ipv6' (bools)
    """
    print("\n" + "=" * 50)
    print("TEST CONFIGURATION")
    print("=" * 50)
    
    # Protocol selection
    print("\nSelect protocols to test:")
    print("-" * 30)
    for key, value in TEST_OPTIONS['protocols'].items():
        default_marker = " (default)" if key == '1' else ""
        print(f"  {key}. {value['name']}{default_marker}")
    
    selected_protocols = None
    while selected_protocols is None:
        try:
            choice = input("\nEnter choice [1-7]: ").strip()
            if not choice:
                choice = '1'
            if choice in TEST_OPTIONS['protocols']:
                selected_protocols = TEST_OPTIONS['protocols'][choice]['tests']
                print(f"  → {', '.join(selected_protocols)}")
            else:
                print("  Invalid choice. Please enter 1-7.")
        except KeyboardInterrupt:
            print("\n\nExiting...")
            sys.exit(0)
    
    # IP version selection (only if both are available)
    skip_ipv4 = False
    skip_ipv6 = False
    
    if ipv4_available and ipv6_available:
        print("\nSelect IP version(s) to test:")
        print("-" * 30)
        for key, value in TEST_OPTIONS['ip_versions'].items():
            default_marker = " (default)" if key == '1' else ""
            print(f"  {key}. {value['name']}{default_marker}")
        
        while True:
            try:
                choice = input("\nEnter choice [1-3]: ").strip()
                if not choice:
                    choice = '1'
                if choice in TEST_OPTIONS['ip_versions']:
                    ip_config = TEST_OPTIONS['ip_versions'][choice]
                    skip_ipv4 = ip_config['skip_ipv4']
                    skip_ipv6 = ip_config['skip_ipv6']
                    print(f"  → {ip_config['name']}")
                    break
                else:
                    print("  Invalid choice. Please enter 1-3.")
            except KeyboardInterrupt:
                print("\n\nExiting...")
                sys.exit(0)
    elif ipv4_available:
        print("\n  ℹ Only IPv4 available - testing IPv4 only")
        skip_ipv6 = True
    elif ipv6_available:
        print("\n  ℹ Only IPv6 available - testing IPv6 only")
        skip_ipv4 = True
    
    return {
        'protocols': selected_protocols,
        'skip_ipv4': skip_ipv4,
        'skip_ipv6': skip_ipv6
    }

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_title():
    title = """

 _   _    _  _____     ____       _                 _               _____         _
| \ | |  / \|_   _|   | __ )  ___| |__   __ ___   _(_) ___  _ __   |_   _|__  ___| |_
|  \| | / _ \ | |_____|  _ \ / _ \ '_ \ / _` \ \ / / |/ _ \| '__|____| |/ _ \/ __| __|
| |\  |/ ___ \| |_____| |_) |  __/ | | | (_| |\ V /| | (_) | | |_____| |  __/\__ \ |_
|_| \_/_/   \_\_|     |____/ \___|_| |_|\__,_| \_/ |_|\___/|_|       |_|\___||___/\__|

        """
    print(title)


def get_network_interfaces():
    """Get all network interfaces with their names and IP addresses (cross-platform)"""
    interfaces = []
    system = platform.system()
    
    try:
        if system == 'Darwin' or system == 'Linux':
            # macOS and Linux: use ifconfig or ip command
            try:
                # Try ifconfig first (works on macOS and many Linux)
                import subprocess
                result = subprocess.run(['ifconfig'], capture_output=True, text=True, timeout=5)
                output = result.stdout
                
                current_if = None
                for line in output.split('\n'):
                    # Check if this is an interface name line
                    if line and not line[0].isspace():
                        # Extract interface name (before the colon)
                        if_name = line.split(':')[0].strip()
                        # Skip loopback
                        if if_name and if_name != 'lo' and if_name != 'lo0':
                            current_if = if_name
                    elif current_if and 'inet ' in line:
                        # Extract IPv4 address
                        parts = line.strip().split()
                        for i, part in enumerate(parts):
                            if part == 'inet' and i + 1 < len(parts):
                                ip = parts[i + 1]
                                # Skip loopback IPs
                                if not ip.startswith('127.'):
                                    interfaces.append({
                                        'name': current_if,
                                        'ip': ip,
                                        'type': 'IPv4'
                                    })
                                break
                    elif current_if and 'inet6 ' in line:
                        # Extract IPv6 address
                        parts = line.strip().split()
                        for i, part in enumerate(parts):
                            if part == 'inet6' and i + 1 < len(parts):
                                ip = parts[i + 1]
                                # Remove zone ID if present
                                ip = ip.split('%')[0]
                                # Skip link-local and loopback
                                if not ip.startswith('fe80') and not ip.startswith('::1'):
                                    interfaces.append({
                                        'name': current_if,
                                        'ip': ip,
                                        'type': 'IPv6'
                                    })
                                break
            except Exception:
                pass
        
        elif system == 'Windows':
            # Windows: use ipconfig command
            try:
                import subprocess
                result = subprocess.run(['ipconfig'], capture_output=True, text=True, timeout=5)
                output = result.stdout
                
                current_if = None
                for line in output.split('\n'):
                    line = line.rstrip()
                    
                    # Check if this is an adapter line
                    if line and not line[0].isspace() and 'adapter' in line:
                        # Extract interface name
                        # Format: "Ethernet adapter Ethernet:" or "Wireless LAN adapter Wi-Fi:"
                        parts = line.split('adapter')
                        if len(parts) >= 2:
                            if_name = parts[1].strip().rstrip(':')
                            # Skip loopback
                            if if_name and 'Loopback' not in if_name:
                                current_if = if_name
                    
                    elif current_if and 'IPv4 Address' in line:
                        # Extract IPv4 address
                        # Format: "   IPv4 Address. . . . . . . . . . . : 192.168.1.100"
                        if ':' in line:
                            ip = line.split(':')[-1].strip()
                            # Remove (Preferred) suffix if present
                            ip = ip.split('(')[0].strip()
                            # Skip loopback IPs
                            if ip and not ip.startswith('127.'):
                                interfaces.append({
                                    'name': current_if,
                                    'ip': ip,
                                    'type': 'IPv4'
                                })
                    
                    elif current_if and 'IPv6 Address' in line and 'Link-local' not in line:
                        # Extract IPv6 address (not link-local)
                        # Format: "   IPv6 Address. . . . . . . . . . . : 2001:db8::1"
                        if ':' in line:
                            parts = line.split(':', 1)
                            if len(parts) >= 2:
                                ip = parts[1].strip()
                                # Remove (Preferred) suffix if present
                                ip = ip.split('(')[0].strip()
                                # Remove zone ID if present (e.g., %12)
                                ip = ip.split('%')[0]
                                # Skip link-local and loopback
                                if ip and not ip.startswith('fe80') and not ip.startswith('::1'):
                                    interfaces.append({
                                        'name': current_if,
                                        'ip': ip,
                                        'type': 'IPv6'
                                    })
            except Exception:
                pass
        
        # Fallback if above methods fail
        if not interfaces:
            # Get default IPs as fallback
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.connect(("8.8.8.8", 80))
                default_ip = sock.getsockname()[0]
                sock.close()
                if default_ip and not default_ip.startswith('127.'):
                    interfaces.append({
                        'name': 'default',
                        'ip': default_ip,
                        'type': 'IPv4'
                    })
            except Exception:
                pass
            
            try:
                sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
                sock.connect(("2001:4860:4860::8888", 80))
                default_ip = sock.getsockname()[0]
                sock.close()
                if default_ip:
                    default_ip = default_ip.split('%')[0]
                    if not default_ip.startswith('fe80') and not default_ip.startswith('::1'):
                        interfaces.append({
                            'name': 'default',
                            'ip': default_ip,
                            'type': 'IPv6'
                        })
            except Exception:
                pass
    except Exception:
        pass
    
    return interfaces

def check_connectivity():
    """Check IPv4 and IPv6 connectivity once at the start"""
    ipv4_available = False
    ipv6_available = False
    
    # Check IPv4
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        sock.connect(("8.8.8.8", 80))
        sock.close()
        ipv4_available = True
    except Exception:
        pass
    
    # Check IPv6
    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        sock.settimeout(2)
        sock.connect(("2001:4860:4860::8888", 80))
        sock.close()
        ipv6_available = True
    except Exception:
        pass
    
    return ipv4_available, ipv6_available

def select_network_interface(interfaces):
    """Let user select which network interface to use"""
    print("\nAvailable Network Interfaces:")
    print("1. Auto-detect (use default interface)")
    
    if not interfaces:
        print("\nNo network interfaces detected. Using auto-detect.")
        return None
    
    # Group interfaces by name
    interface_groups = {}
    for iface in interfaces:
        name = iface['name']
        if name not in interface_groups:
            interface_groups[name] = {'name': name, 'ipv4': None, 'ipv6': None}
        if iface['type'] == 'IPv4':
            interface_groups[name]['ipv4'] = iface['ip']
        elif iface['type'] == 'IPv6':
            interface_groups[name]['ipv6'] = iface['ip']
    
    # Display grouped interfaces
    interface_list = list(interface_groups.values())
    for idx, iface in enumerate(interface_list, start=2):
        ips = []
        if iface['ipv4']:
            ips.append(f"IPv4: {iface['ipv4']}")
        if iface['ipv6']:
            ips.append(f"IPv6: {iface['ipv6']}")
        print(f"{idx}. {iface['name']:<10} {', '.join(ips)}")
    
    while True:
        try:
            choice = input(f"\nSelect interface (1-{len(interface_list) + 1}): ").strip()
            if not choice:
                print("Error: Please select an interface.")
                continue
            
            choice_num = int(choice)
            if choice_num == 1:
                return None  # Auto-detect
            elif 2 <= choice_num <= len(interface_list) + 1:
                selected = interface_list[choice_num - 2]
                return selected
            else:
                print(f"Error: Please enter a number between 1 and {len(interface_list) + 1}.")
        except ValueError:
            print("Error: Please enter a valid number.")
        except KeyboardInterrupt:
            print("\n\nExiting...")
            sys.exit(0)

def print_stun_servers():
    print("\nSelect STUN server:")
    for i, server in enumerate(STUN_SERVERS, 1):
        print(f"{i}. {server}")

def is_valid_domain(domain):
    """
    Check if the domain follows a valid format
    """
    # Handle empty input
    if not domain:
        return False
    
    domain = domain.strip()
    if not domain:
        return False
    
    # Check for IP address (IPv4)
    try:
        # Try to create an IPv4 address object
        socket.inet_pton(socket.AF_INET, domain)
        return True  # Valid IPv4
    except socket.error:
        pass  # Not an IPv4 address, continue to domain validation
    
    # Check for domain name format using precompiled patterns
    try:
        # Standard domain name format validation
        # This allows domains with multiple labels (e.g., example.com, sub.example.com)
        # Each label must start and end with alphanumeric and can contain hyphens in the middle
        if DOMAIN_PATTERN.match(domain) is not None:
            return True
            
        # Allow numeric TLDs (some special domains end in numbers)
        return DOMAIN_PATTERN_NUMERIC_TLD.match(domain) is not None
    except Exception:
        return False  # Any regex error means invalid domain

def get_stun_server_choice():
    while True:
        user_input = input(f"Enter STUN server number (1-{len(STUN_SERVERS)}): ").strip()
        
        # Check for empty input
        if not user_input:
            print("Error: Please enter a server number.")
            continue
            
        # Check if input is numeric
        if not user_input.isdigit():
            print("Error: Please enter a numeric value.")
            continue
            
        # Convert and validate range
        choice = int(user_input)
        if 1 <= choice <= len(STUN_SERVERS):
            # If custom server is selected
            if choice == len(STUN_SERVERS):  # Custom Server option
                while True:
                    custom_input = input("Enter custom STUN server as domain:port (e.g., stun.example.com:3478, default port if omitted): ")
                    
                    # Handle empty input
                    if not custom_input.strip():
                        print("Error: Please enter a STUN server.")
                        continue
                        
                    # Check if the input contains a port
                    if ':' in custom_input:
                        # Extract domain and port
                        try:
                            # Take the last colon as the separator between domain and port
                            server, port_str = custom_input.rsplit(':', 1)
                        except Exception:
                            print("Error: Invalid input format.")
                            continue
                            
                        # Track validation errors
                        errors = []
                        
                        # Validate domain
                        if not server or not is_valid_domain(server):
                            errors.append("Invalid domain format")
                            
                        # Validate port
                        try:
                            if not port_str:
                                errors.append("Empty port")
                                port = None
                            else:
                                port = int(port_str)
                                if not (1 <= port <= 65535):
                                    errors.append(f"Port {port} is outside valid range (1-65535)")
                        except ValueError:
                            errors.append(f"Port '{port_str}' is not a number")
                            port = None
                            
                        # Report all errors or return valid input
                        if errors:
                            print(f"Error: {' and '.join(errors)}.")
                            continue
                        else:
                            return (server, port)
                    else:
                        # If no port specified, check if domain is valid
                        if custom_input.strip() and is_valid_domain(custom_input):
                            return (custom_input, None)  # Return with default port
                        else:
                            print("Error: Invalid domain format.")
                            continue
            else:
                # Return predefined server with default port
                return (STUN_SERVERS[choice - 1], None)
        else:
            print(f"Error: '{user_input}' is not a valid option. Choose between 1-{len(STUN_SERVERS)}.")
            continue

def run_test(script_name, stun_server_info, skip_ipv4=False, skip_ipv6=False, interface=None):
    try:
        server, port = stun_server_info
        
        # Prepare command with server and optional port
        cmd = [sys.executable, script_name, server]
        if port is not None:
            cmd.append(str(port))
        if skip_ipv4:
            cmd.append('--skip-ipv4')
        if skip_ipv6:
            cmd.append('--skip-ipv6')
        if interface:
            # Pass both IPv4 and IPv6 if available
            if interface.get('ipv4'):
                cmd.append('--interface-ipv4')
                cmd.append(interface['ipv4'])
            if interface.get('ipv6'):
                cmd.append('--interface-ipv6')
                cmd.append(interface['ipv6'])
            
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        
        # Print the output in real-time
        print(result.stdout, end='')
        if result.stderr:
            print(result.stderr, end='')
        
        # Parse the output to extract behaviors for both IPv4 and IPv6
        behaviors = {'ipv4': {}, 'ipv6': {}}
        current_ip_version = None
        
        for line in result.stdout.split('\n'):
            # Detect IP version section
            if 'Testing IPv4' in line:
                current_ip_version = 'ipv4'
            elif 'Testing IPv6' in line:
                current_ip_version = 'ipv6'
            
            # Extract behaviors or failure status based on current section
            if current_ip_version:
                if 'Binding status: Failed' in line:
                    behaviors[current_ip_version]['status'] = 'failed'
                elif 'Mapping behavior:' in line:
                    behaviors[current_ip_version]['mapping'] = line.split('Mapping behavior:')[1].strip()
                elif 'Filtering behavior:' in line:
                    behaviors[current_ip_version]['filtering'] = line.split('Filtering behavior:')[1].strip()
        
        # Return behaviors if we found any, otherwise mark as completed
        if behaviors['ipv4'] or behaviors['ipv6']:
            return behaviors
        else:
            return {'status': 'completed'}
    except subprocess.CalledProcessError as e:
        print(f"An error occured while running {script_name}: {e}")
        return {'status': 'failed'}
    except FileNotFoundError:
        print(f"Error: {script_name} not found.")
        return {'status': 'failed'}

def main():
    clear_screen()
    print_title()
    
    # Check connectivity once
    print("Checking network connectivity...")
    ipv4_available, ipv6_available = check_connectivity()
    
    print(f"\n{'=' * 50}")
    print("NETWORK CONNECTIVITY")
    print(f"{'=' * 50}")
    print(f"  IPv4: {'✓ Available' if ipv4_available else '✗ Not Available'}")
    print(f"  IPv6: {'✓ Available' if ipv6_available else '✗ Not Available'}")
    
    if not ipv4_available and not ipv6_available:
        print("\nNo network connectivity detected. Cannot run tests.")
        return
    
    # Let user select which tests to run
    test_config = select_test_options(ipv4_available, ipv6_available)
    selected_protocols = test_config['protocols']
    skip_ipv4 = test_config['skip_ipv4']
    skip_ipv6 = test_config['skip_ipv6']
    
    # Get network interfaces and let user select
    interfaces = get_network_interfaces()
    selected_interface = select_network_interface(interfaces)
    
    if selected_interface:
        ips = []
        if selected_interface['ipv4']:
            ips.append(f"IPv4: {selected_interface['ipv4']}")
        if selected_interface['ipv6']:
            ips.append(f"IPv6: {selected_interface['ipv6']}")
        print(f"\n  → Using interface: {selected_interface['name']} ({', '.join(ips)})")
    else:
        print("\n  → Using auto-detected default interface")
    
    print_stun_servers()
    stun_server_info = get_stun_server_choice()
    
    # Build the list of tests to run based on user selection
    all_tests = {
        'UDP': ("RFC5780-UDP.py", "UDP"),
        'TCP': ("RFC5780-TCP.py", "TCP"),
        'TLS': ("RFC5780-TLS.py", "TLS")
    }
    
    tests = [all_tests[proto] for proto in selected_protocols if proto in all_tests]
    
    print(f"\n{'=' * 50}")
    print("RUNNING TESTS")
    print(f"{'=' * 50}")
    print(f"  Protocols: {', '.join(selected_protocols)}")
    ip_versions = []
    if not skip_ipv4:
        ip_versions.append("IPv4")
    if not skip_ipv6:
        ip_versions.append("IPv6")
    print(f"  IP Versions: {', '.join(ip_versions)}")
    print(f"  Server: {stun_server_info[0]}")
    
    results = []
    for script, protocol in tests:
        print(f"\n{'─' * 50}")
        print(f"  {protocol} Test")
        print(f"{'─' * 50}")
        behaviors = run_test(script, stun_server_info, skip_ipv4, skip_ipv6, selected_interface)
        results.append((protocol, behaviors))
    
    # Summary - Display as table
    print(f"\n{'=' * 90}")
    print("SUMMARY")
    print(f"{'=' * 90}")
    
    # Prepare table data
    table_rows = []
    for protocol, behaviors in results:
        if 'status' in behaviors:
            if behaviors['status'] == 'failed':
                table_rows.append([f"{protocol} (IPv4/IPv6)", 'FAILED', '-'])
        else:
            # IPv4 results
            if behaviors.get('ipv4'):
                if behaviors['ipv4'].get('status') == 'failed':
                    table_rows.append([f"{protocol} (IPv4)", 'FAILED', '-'])
                else:
                    mapping = behaviors['ipv4'].get('mapping', '-')
                    filtering = behaviors['ipv4'].get('filtering', '-')
                    table_rows.append([f"{protocol} (IPv4)", mapping, filtering])
            
            # IPv6 results
            if behaviors.get('ipv6'):
                if behaviors['ipv6'].get('status') == 'failed':
                    table_rows.append([f"{protocol} (IPv6)", 'FAILED', '-'])
                else:
                    mapping = behaviors['ipv6'].get('mapping', '-')
                    filtering = behaviors['ipv6'].get('filtering', '-')
                    table_rows.append([f"{protocol} (IPv6)", mapping, filtering])
    
    # Print table header
    print(f"{'Protocol':<18} {'Mapping Behavior':<35} {'Filtering Behavior':<35}")
    print(f"{'-' * 18} {'-' * 35} {'-' * 35}")
    
    # Print table rows
    for row in table_rows:
        protocol_ver, mapping, filtering = row
        print(f"{protocol_ver:<18} {mapping:<35} {filtering:<35}")
    
    print(f"{'=' * 90}\n")

if __name__ == "__main__":
    main()
