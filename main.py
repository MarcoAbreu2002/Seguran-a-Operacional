import os
import sys
import modbus
import dnp3

def clear_terminal():
    """Clear the terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')

def display_header():
    """Display the header information."""
    print("=" * 50)
    print("INSTITUTO POLITÉCNICO DE BEJA")
    print("ESCOLA SUPERIOR DE TECNOLOGIA E GESTÃO")
    print("MESTRADO EM ENGENHARIA DE SEGURANÇA INFORMÁTICA")
    print("Cibersegurança em Infraestruturas Críticas")
    print("2024/2025")
    print("Alunos: M.Abreu P.Proença")
    print("Professor: Prof. Dr. Daniel Franco")
    print("=" * 50)

def display_menu():
    """Display the main menu."""
    print("\nPlease select an option:")
    print("1 - Modbus Protocol Manipulation")
    print("2 - DNP3 Protocol Data Extraction")
    print("3 - About the Project")
    print("4 - Exit")
    print("=" * 50)

def about_project():
    """Display information about the project."""
    clear_terminal()
    display_header()
    print("\nProject Details:\n")
    print("1. Modbus/TCP Protocol:")
    print("   - Manipulate Source and Destination IP Addresses")
    print("   - Manipulate Source and Destination MAC Addresses")
    print("   - Manipulate Modbus Registers\n")
    print("2. DNP3 Protocol:")
    print("   - Extract information from DNP3 packets")
    print("   - Save information to a text file\n")
    input("Press Enter to return to the menu...")

def main():
    """Main program function with menu handling."""
    while True:
        clear_terminal()
        display_header()
        display_menu()
        
        try:
            choice = int(input("Enter your choice: "))
            if choice == 1:
                clear_terminal()
                print("Running Modbus Protocol Manipulation...")
                modbus.main()  # Call the main function in modbus.py
                input("\nPress Enter to return to the menu...")
            elif choice == 2:
                clear_terminal()
                print("Running DNP3 Protocol Data Extraction...")
                dnp3.main()  # Call the main function in dnp3.py
                input("\nPress Enter to return to the menu...")
            elif choice == 3:
                about_project()
            elif choice == 4:
                print("Exiting program. Goodbye!")
                sys.exit(0)
            else:
                print("Invalid choice. Please try again.")
                input("Press Enter to return to the menu...")
        except ValueError:
            print("Invalid input. Please enter a number.")
            input("Press Enter to return to the menu...")

if __name__ == "__main__":
    main()
