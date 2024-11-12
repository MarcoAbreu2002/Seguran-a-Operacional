from scapy.all import PcapReader, wrpcap
import scapy.contrib.modbus as mb  
import scapy.all as scapy
import os
import struct
import ipaddress
import re
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether
from concurrent.futures import ThreadPoolExecutor


def print_menu():
    """Display the main menu with options."""
    print("\n" + "=" * 50)
    print("Modbus packet manipulater Menu")
    print("=" * 50)
    print("1 - Manipulate Modbus packets")
    print("2 - Leave")
    print("=" * 50)


def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_valid_mac(mac):
    return bool(re.match(r"^([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2})$", mac))



def display_packet_info(packets):
    # Ask the user once if they want to see the raw packet data
    show_raw = input("Deseja ver os dados brutos de todos os pacotes? (s/n): ").lower()
    
    # Display each packet's communication pair and Modbus data
    for i, packet in enumerate(packets):
        print(f"\n{'-'*50}")
        print(f"Packet {i + 1}:")
        
        if packet.haslayer(scapy.IP) and packet.haslayer(scapy.Ether):
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst
            src_mac = packet[scapy.Ether].src
            dst_mac = packet[scapy.Ether].dst

            print(f"  Communication Pair: {src_ip} ({src_mac}) -> {dst_ip} ({dst_mac})")
        
        # Show raw packet data if the user opted to see it
        if show_raw == 's':
            print("\nRaw Packet Data:")
            packet.show()
        
        # Display Modbus Registers if available
        registers = get_modbus_registers(packet)
        if registers:
            print(f"\nModbus Registers for Packet {i + 1} ({src_ip} -> {dst_ip}):")
            for idx, register in enumerate(registers):
                print(f"  Register {idx + 1}: {register}")
        else:
            print("No Modbus registers available for this packet.")
        
        print(f"{'-'*50}\n")





# Update the `get_modbus_registers` function to access Modbus register data
def get_modbus_registers(packet):
    """
    Extract Modbus register data from the Modbus/TCP payload.
    """
    registers = []  # Initialize registers as an empty list

    if packet.haslayer(mb.ModbusADURequest) or packet.haslayer(mb.ModbusADUResponse):
        modbus_layer = packet.getlayer(mb.ModbusADURequest) or packet.getlayer(mb.ModbusADUResponse)
        
        # Access specific Modbus fields like function code and byte count if available
        byte_count = getattr(modbus_layer, 'byte_count', 0)
        
        # Check if the Modbus layer has the `registerVal` attribute
        if hasattr(modbus_layer, 'registerVal'):
            registers = modbus_layer.registerVal
        data = getattr(modbus_layer, 'data', b'')

        # Unpack data into registers (each register is 2 bytes)
        for i in range(0, byte_count, 2):
            registers.append(struct.unpack(">H", data[i:i+2])[0])  # Big-endian 2-byte register
    return registers

def get_user_modifications(packets):
    while True:
        display_packet_info(packets)  # Display all packets initially
        
        change = input("\nDeseja alterar algum dos pacotes exibidos? (s/n): ")
        if change.lower() == 'n':
            break
        elif change.lower() == 's':
            packet_num = int(input("Digite o número do pacote que deseja alterar: ")) - 1
            if packet_num < 0 or packet_num >= len(packets):
                print("Número de pacote inválido.")
                continue
            
            # Retrieve the selected packet
            packet = packets[packet_num]
            
            # Display only the selected packet for reference
            print("\nInformações do Pacote Selecionado:")
            display_single_packet_info(packet, packet_num)  # New helper function to display one packet
            
            while True:
                option = input("Escolha uma opção: 1 - Alterar pares de comunicação, 2 - Alterar dados Modbus, 3 - Voltar para a lista: ")
                if option == '1':
                    modify_communication_pair(packet)
                elif option == '2':
                    # Prompt user to modify Modbus registers (show all registers)
                    registers = get_modbus_registers(packet)
                    if registers:
                        print("\nRegistros Modbus atuais:")
                        for i, reg in enumerate(registers):
                            print(f"Registro {i + 1}: {reg}")

                        # Update Modbus registers interactively
                        for i in range(len(registers)):
                            new_value = input(f"Digite o novo valor para o Registro {i + 1} (deixe em branco para manter o valor atual): ")
                            if new_value:
                                try:
                                    # Convert the input to integer (decimal)
                                    registers[i] = int(new_value)
                                except ValueError:
                                    print(f"Valor inválido para o Registro {i + 1}. O valor original será mantido.")

                        # Update Modbus registers in the packet
                        update_modbus_registers(packet, registers)
                        print("Dados Modbus alterados com sucesso.")
                    else:
                        print("Não há registros Modbus para alterar neste pacote.")
                elif option == '3':
                    break
                else:
                    print("Opção inválida. Tente novamente.")
        else:
            print("Opção inválida. Digite 's' para sim ou 'n' para não.")

def update_modbus_registers(packet, registers):
    """
    Modify the Modbus registers in the packet with the new values.
    """
    modbus_layer = packet.getlayer(mb.ModbusADURequest) or packet.getlayer(mb.ModbusADUResponse)
    if modbus_layer:
        byte_count = len(registers) * 2  # Each register is 2 bytes
        data = b''.join(struct.pack(">H", register) for register in registers)

        # Update Modbus layer with the new byte count and data
        modbus_layer.byte_count = byte_count
        modbus_layer.data = data

        # Recalculate checksums if necessary
        if packet.haslayer(scapy.IP):
            del packet[scapy.IP].chksum
        if packet.haslayer(scapy.TCP):
            del packet[scapy.TCP].chksum

        print(f"Modbus registers updated: {registers}")

def display_single_packet_info(packet, packet_num):
    separator = "-" * 60
    print(separator)
    print(f"Packet {packet_num + 1}")
    print(separator)

    # Display IP and MAC details if available
    if packet.haslayer(scapy.IP) and packet.haslayer(scapy.Ether):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        src_mac = packet[scapy.Ether].src
        dst_mac = packet[scapy.Ether].dst

        # Print communication details
        print(f"{'Source IP':<15}: {src_ip}")
        print(f"{'Destination IP':<15}: {dst_ip}")
        print(f"{'Source MAC':<15}: {src_mac}")
        print(f"{'Destination MAC':<15}: {dst_mac}")

    # Display raw packet data
    print("\nRaw Packet Data:")
    packet.show()

    # Display Modbus registers if they exist
    registers = get_modbus_registers(packet)
    if registers:
        print(f"\nModbus Registers for Packet {packet_num + 1} ({src_ip} -> {dst_ip}):")
        print(f"{'Register':<10}{'Value':<10}")
        print("-" * 20)
        for j, register in enumerate(registers):
            print(f"{j:<10}{register:<10}")
    else:
        print("No Modbus registers available for this packet.")
    print(separator)





def modify_communication_pair(packet):
    if packet.haslayer(scapy.IP) and packet.haslayer(scapy.Ether):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        src_mac = packet[scapy.Ether].src
        dst_mac = packet[scapy.Ether].dst

        # Update communication pair details
        new_src_ip = get_user_confirmation(src_ip, "IP de origem")
        new_dst_ip = get_user_confirmation(dst_ip, "IP de destino")
        new_src_mac = get_user_confirmation(src_mac, "MAC de origem")
        new_dst_mac = get_user_confirmation(dst_mac, "MAC de destino")

        # Apply changes to the packet
        packet[scapy.IP].src = new_src_ip
        packet[scapy.IP].dst = new_dst_ip
        packet[scapy.Ether].src = new_src_mac
        packet[scapy.Ether].dst = new_dst_mac
        # Recalculate checksums
        del packet[scapy.IP].chksum
        if packet.haslayer(scapy.TCP):
            del packet[scapy.TCP].chksum
        print("Pares de comunicação alterados com sucesso.")


def get_user_confirmation(current_value, value_type):
    while True:
        new_value = input(f"O valor atual de {value_type} é {current_value}. Deseja alterar? (s/n): ")
        if new_value.lower() == 's':
            new_value = input(f"Digite o novo valor de {value_type}: ")
            if (value_type.startswith("IP") and is_valid_ip(new_value)) or \
               (value_type.startswith("MAC") and is_valid_mac(new_value)):
                return new_value
            else:
                print(f"Erro: {value_type} inserido não é válido. Tente novamente.")
        elif new_value.lower() == 'n':
            return current_value
        else:
            print("Opção inválida. Digite 's' para sim ou 'n' para não.")

def manipulate_pcap(file_name):
    print(f"Manipulando pacotes no arquivo: {file_name}")
    
    # Use a list to store packets only if user wishes to modify them
    packets = []
    with PcapReader(file_name) as pcap_reader:
        for packet in pcap_reader:
            packets.append(packet)  # Store each packet temporarily in memory

    # Process user modifications
    get_user_modifications(packets)

    # Save the modified packets
    manipulated_file = "manipulated_" + file_name
    wrpcap(manipulated_file, packets)
    print(f"\nPacotes manipulados e salvos em '{manipulated_file}'.")
def main():
    while True:
        print_menu()
        choice = input("Escolha uma opção: ")
        
        if choice == '1':
            file_name = input("Digite o nome do arquivo PCAP para manipulação: ")
            if os.path.exists(file_name):
                manipulate_pcap(file_name)
            else:
                print("Arquivo não encontrado.")
        
        elif choice == '2':
            print("Saindo do programa.")
            break
        
        else:
            print("Opção inválida. Tente novamente.")

if __name__ == "__main__":
    main()
