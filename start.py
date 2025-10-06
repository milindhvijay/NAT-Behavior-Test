import os
import subprocess
import sys
import re
import socket

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

def print_menu():
    print("1. RFC5780 - UDP")
    print("2. RFC5780 - TCP")
    print("3. RFC5780 - TLS")
    print("4. Exit")

def get_user_choice():
    while True:
        user_input = input("Enter your choice (1-4): ").strip()
        
        # Check for empty input
        if not user_input:
            print("Error: Please enter a choice (1-4).")
            continue
            
        # Check if input is numeric
        if not user_input.isdigit():
            print("Error: Please enter a numeric value (1-4).")
            continue
            
        # Convert and validate range
        choice = int(user_input)
        if 1 <= choice <= 4:
            return choice
        else:
            print(f"Error: '{user_input}' is not a valid option. Choose between 1-4.")


def print_stun_servers():
    print("\nSelect STUN server:")
    for i, server in enumerate(STUN_SERVERS, 1):
        print(f"{i}. {server}")

def is_valid_domain(domain):
    """
    Check if the domain follows a valid format
    """
    # Handle empty input
    if not domain or not domain.strip():
        return False
        
    domain = domain.strip()
    
    # Check for IP address (IPv4)
    try:
        # Try to create an IPv4 address object
        socket.inet_pton(socket.AF_INET, domain)
        return True  # Valid IPv4
    except socket.error:
        pass  # Not an IPv4 address, continue to domain validation
    
    # Check for domain name format
    try:
        # Standard domain name format validation
        # This allows domains with multiple labels (e.g., example.com, sub.example.com)
        # Each label must start and end with alphanumeric and can contain hyphens in the middle
        pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        if re.match(pattern, domain) is not None:
            return True
            
        # Allow numeric TLDs (some special domains end in numbers)
        pattern_with_numeric_tld = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z0-9]{2,}$'
        return re.match(pattern_with_numeric_tld, domain) is not None
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

def run_test(script_name, stun_server_info):
    try:
        server, port = stun_server_info
        
        # Prepare command with server and optional port
        cmd = [sys.executable, script_name, server]
        if port is not None:
            cmd.append(str(port))
            
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f"An error occured while running {script_name}: {e}")
    except FileNotFoundError:
        print(f"Error: {script_name} not found.")

def main():
    while True:
        clear_screen()
        print_title()
        print_menu()
        choice = get_user_choice()
        
        if choice == 4:
            break
            
        print_stun_servers()
        stun_server_info = get_stun_server_choice()
        
        if choice == 1:
            run_test("RFC5780-UDP.py", stun_server_info)
        elif choice == 2:
            run_test("RFC5780-TCP.py", stun_server_info)
        elif choice == 3:
            run_test("RFC5780-TLS.py", stun_server_info)

        input("\nPress Enter to return to the main menu...")

if __name__ == "__main__":
    main()
