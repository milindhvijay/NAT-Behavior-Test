import os
import subprocess
import sys

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
        try:
            choice = int(input("Enter your choice (1-4): "))
            if 1 <=choice <= 4:
                return choice
            else:
                print("Invalid choice.")
        except ValueError:
            print("Invalid input.")

def run_test(script_name):
    try:
        subprocess.run([sys.executable, script_name], check=True)
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

        if choice == 1:
            run_test("RFC5780-UDP.py")
        elif choice == 2:
            run_test("RFC5780-TCP.py")
        elif choice == 3:
            run_test("RFC5780-TLS.py")
        elif choice == 4:
            break

        input("\nPress Enter to return to the main menu...")

if __name__ == "__main__":
    main()
