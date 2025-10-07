import os
import subprocess
import sys
import re
import socket

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

def run_test(script_name, stun_server_info, skip_ipv6=False):
    try:
        server, port = stun_server_info
        
        # Prepare command with server and optional port
        cmd = [sys.executable, script_name, server]
        if port is not None:
            cmd.append(str(port))
        if skip_ipv6:
            cmd.append('--skip-ipv6')
            
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
    
    print(f"\n{'=' * 70}")
    print("NETWORK CONNECTIVITY")
    print(f"{'=' * 70}")
    print(f"IPv4: {'Available' if ipv4_available else 'Not Available'}")
    print(f"IPv6: {'Available' if ipv6_available else 'Not Available'}")
    print(f"{'=' * 70}")
    
    if not ipv4_available and not ipv6_available:
        print("\nNo network connectivity detected. Cannot run tests.")
        return
    
    print_stun_servers()
    stun_server_info = get_stun_server_choice()
    
    print()  # Add one blank line after server selection
    
    # Run all three tests sequentially
    tests = [
        ("RFC5780-UDP.py", "UDP"),
        ("RFC5780-TCP.py", "TCP"),
        ("RFC5780-TLS.py", "TLS")
    ]
    
    skip_ipv6 = not ipv6_available
    
    results = []
    for script, protocol in tests:
        print(f"\n{'#' * 70}")
        print(f"# {protocol} Test")
        print(f"{'#' * 70}\n")
        behaviors = run_test(script, stun_server_info, skip_ipv6)
        results.append((protocol, behaviors))
    
    # Summary
    print(f"\n{'=' * 70}")
    print("SUMMARY")
    print(f"{'=' * 70}")
    for protocol, behaviors in results:
        if 'status' in behaviors:
            if behaviors['status'] == 'failed':
                print(f"{protocol}:")
                print(f"  FAILED")
            else:
                print(f"{protocol}:")
                print(f"  ✓ COMPLETED")
        else:
            print(f"{protocol}:")
            # Display IPv4 results
            if behaviors.get('ipv4'):
                print(f"  IPv4:")
                if behaviors['ipv4'].get('status') == 'failed':
                    print(f"    FAILED")
                else:
                    if 'mapping' in behaviors['ipv4']:
                        print(f"    Mapping:    {behaviors['ipv4']['mapping']}")
                    if 'filtering' in behaviors['ipv4']:
                        print(f"    Filtering:  {behaviors['ipv4']['filtering']}")
            # Display IPv6 results
            if behaviors.get('ipv6'):
                print(f"  IPv6:")
                if behaviors['ipv6'].get('status') == 'failed':
                    print(f"    FAILED")
                else:
                    if 'mapping' in behaviors['ipv6']:
                        print(f"    Mapping:    {behaviors['ipv6']['mapping']}")
                    if 'filtering' in behaviors['ipv6']:
                        print(f"    Filtering:  {behaviors['ipv6']['filtering']}")
    print(f"{'=' * 70}\n")

if __name__ == "__main__":
    main()
