import os
import sys
import modbus
import dnp3

def clear_terminal():
    """Clear the terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')

def color_text(text, color_code):
    """Wrap text in ANSI color codes."""
    return f"\033[{color_code}m{text}\033[0m"

def display_header():
    """Display the header information with styling."""
    print(color_text("=" * 50, "36"))
    print(color_text("INSTITUTO POLITÉCNICO DE BEJA", "1;34"))
    print("ESCOLA SUPERIOR DE TECNOLOGIA E GESTÃO")
    print("MESTRADO EM ENGENHARIA DE SEGURANÇA INFORMÁTICA")
    print(color_text("Cibersegurança em Infraestruturas Críticas", "1;33"))
    print("2024/2025")
    print("Alunos: M.Abreu, P.Proença")
    print("Professor: Prof. Dr. Daniel Franco")
    print(color_text("=" * 50, "36"))

def display_menu():
    """Display the main menu with color and formatting."""
    print("\n" + color_text("MAIN MENU", "1;32"))
    print("=" * 50)
    print(color_text("1", "1;36") + " - Modbus Protocol Manipulation")
    print(color_text("2", "1;36") + " - DNP3 Protocol Data Extraction")
    print(color_text("3", "1;36") + " - About the Project")
    print(color_text("4", "1;36") + " - Exit")
    print("=" * 50)

def about_project():
    """Display information about the project in a structured format."""
    clear_terminal()
    display_header()
    print("\n" + color_text("PROJECT DETAILS", "1;32"))
    print("=" * 50)
    print(color_text("1. Modbus/TCP Protocol:", "1;34"))
    print("   - Manipulate Source and Destination IP Addresses")
    print("   - Manipulate Source and Destination MAC Addresses")
    print("   - Manipulate Modbus Registers")
    print()
    print(color_text("2. DNP3 Protocol:", "1;34"))
    print("   - Extract information from DNP3 packets")
    print("   - Save information to a text file")
    print("=" * 50)
    input(color_text("Press Enter to return to the menu...", "1;32"))

def main():
    """Main program function with menu handling and styling."""
    while True:
        clear_terminal()
        display_header()
        display_menu()
        
        try:
            choice = int(input(color_text("Enter your choice: ", "1;33")))
            if choice == 1:
                clear_terminal()
                print(color_text("Running Modbus Protocol Manipulation...", "1;35"))
                modbus.main()  # Call the main function in modbus.py
                input(color_text("\nPress Enter to return to the menu...", "1;32"))
            elif choice == 2:
                clear_terminal()
                print(color_text("Running DNP3 Protocol Data Extraction...", "1;35"))
                dnp3.main()  # Call the main function in dnp3.py
                input(color_text("\nPress Enter to return to the menu...", "1;32"))
            elif choice == 3:
                about_project()
            elif choice == 4:
                print(color_text("Exiting program. Goodbye!", "1;31"))
                sys.exit(0)
            else:
                print(color_text("Invalid choice. Please try again.", "1;31"))
                input(color_text("Press Enter to return to the menu...", "1;32"))
        except ValueError:
            print(color_text("Invalid input. Please enter a number.", "1;31"))
            input(color_text("Press Enter to return to the menu...", "1;32"))

if __name__ == "__main__":
    main()
