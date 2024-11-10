import scapy.all as scapy
import scapy.contrib.modbus as mb  
import os
import ipaddress
import re
from concurrent.futures import ThreadPoolExecutor
import struct

def print_menu():
    print("""
                 1 - Manipular Pacotes Modbus/TCP
                 2 - Sair
    """)

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_valid_mac(mac):
    return bool(re.match(r"^([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2})$", mac))

def get_user_modifications(communication_pairs, packets):
    modifications = {}

    # Display all communication pairs
    print("\nLista de linhas de comunicação detectadas:")
    for i, (src_ip, dst_ip, src_mac, dst_mac) in enumerate(communication_pairs, start=1):
        print(f"\n{i} - Nova linha de comunicação detectada: {src_ip} -> {dst_ip}")
        print(f"   IP de origem: {src_ip}")
        print(f"   IP de destino: {dst_ip}")
        print(f"   MAC de origem: {src_mac}")
        print(f"   MAC de destino: {dst_mac}")
    
    # Ask if the user wants to make any modifications
    modify = input("\nDeseja alterar algum par de comunicação? (s/n): ")
    if modify.lower() != 's':
        return modifications  # No modifications needed

    # Loop until the user is done making changes
    while True:
        # Ask which communication pair to modify
        pair_index = input("\nDigite o número do par que deseja alterar ou 'q' para sair: ")
        if pair_index.lower() == 'q':
            break  # Exit the loop if the user is done
        try:
            pair_index = int(pair_index) - 1
            if pair_index < 0 or pair_index >= len(communication_pairs):
                print("Número inválido. Tente novamente.")
                continue
        except ValueError:
            print("Entrada inválida. Digite um número válido ou 'q' para sair.")
            continue

        # Get the selected communication pair
        src_ip, dst_ip, src_mac, dst_mac = list(communication_pairs)[pair_index]

        # Prompt for modifications for the selected pair
        new_src_ip = get_user_confirmation(src_ip, "IP de origem")
        new_dst_ip = get_user_confirmation(dst_ip, "IP de destino")
        new_src_mac = get_user_confirmation(src_mac, "MAC de origem")
        new_dst_mac = get_user_confirmation(dst_mac, "MAC de destino")
        
        # Extract the Modbus registers from the selected packet
        packet = packets[pair_index + 1]
        packet.show()
        if packet and packet.haslayer(scapy.TCP) and packet.haslayer('Modbus'):
            registers = get_modbus_registers(packet)
            if registers:
                print(f"\nModbus Registers para {pair_index + 1} - {src_ip} -> {dst_ip}:")
                for i, register in enumerate(registers):
                    print(f"  Registro {i}: {register}")

                # Ask user to modify register values
                for i, register in enumerate(registers):
                    new_value = input(f"Digite o novo valor para o registro {i} (atualmente {register}): ")
                    if new_value.isdigit():
                        registers[i] = int(new_value)

                # Update packet with modified register values
                update_modbus_registers(packet, registers)
        else:
            print("O pacote selecionado não possui registros no Modbus.")
        # Store modifications for the selected pair
        modifications[(src_ip, dst_ip, src_mac, dst_mac)] = (new_src_ip, new_dst_ip, new_src_mac, new_dst_mac)

    return modifications


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

# Update the `get_modbus_registers` function to access Modbus register data
def get_modbus_registers(packet):
    """
    Extract Modbus register data from the Modbus/TCP payload.
    """
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
    return []

# Update the `update_modbus_registers` function to modify Modbus data
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

# Modify `manipulate_packet` to handle Modbus layers correctly
def manipulate_packet(packet, modifications, original_values):
    src_ip, dst_ip, src_mac, dst_mac = original_values
    if packet.haslayer(scapy.IP) and packet.haslayer(scapy.Ether):
        # Retrieve modifications for this communication pair
        new_src_ip, new_dst_ip, new_src_mac, new_dst_mac = modifications[(src_ip, dst_ip, src_mac, dst_mac)]
        
        # Modify IPs and MACs
        packet[scapy.IP].src = new_src_ip
        packet[scapy.IP].dst = new_dst_ip
        packet[scapy.Ether].src = new_src_mac
        packet[scapy.Ether].dst = new_dst_mac

        # After modifying IP and MAC, show Modbus details and ask for changes
        if packet.haslayer(mb.ModbusADURequest) or packet.haslayer(mb.ModbusADUResponse):
            registers = get_modbus_registers(packet)
            # Modified part of `get_user_modifications` for displaying registers and selectively updating
            if registers:
                # Display all registers first
                print(f"\nModbus Registers para {src_ip} -> {dst_ip}:")
                for i, register in enumerate(registers):
                    print(f"  Registro {i}: {register}")

                # Ask if the user wants to change any register values
                modify_registers = input("\nDeseja alterar algum registro? (s/n): ")
                while modify_registers.lower() == 's':
                    # Get the index of the register to modify
                    try:
                        register_index = int(input("Qual registro deseja alterar? "))
                        if 0 <= register_index < len(registers):
                            # Prompt for the new value of the selected register
                            new_value = input(f"Digite o novo valor para o registro {register_index} (atualmente {registers[register_index]}): ")
                            if new_value.isdigit():
                                registers[register_index] = int(new_value)  # Update the register value
                                print(f"Registro {register_index} atualizado para {new_value}.")
                            else:
                                print("Valor inválido. Por favor, insira um número.")
                        else:
                            print("Índice de registro inválido.")
                    except ValueError:
                        print("Entrada inválida. Por favor, insira um número de índice.")

                    # Ask if they want to modify another register
                    modify_registers = input("\nDeseja alterar outro registro? (s/n): ")
                    
                # Update packet with modified register values
                update_modbus_registers(packet, registers)


        # Recalculate checksums
        del packet[scapy.IP].chksum  # Let Scapy recalculate the IP checksum
        if packet.haslayer(scapy.TCP):
            del packet[scapy.TCP].chksum  # Let Scapy recalculate the TCP checksum
    
    return packet

def get_display_preference():
    """
    Ask the user if they want to display only unique communication pairs or all packets.
    
    Returns:
        bool: True if the user wants to display only unique communication pairs, False if they want to display all packets.
    """
    while True:
        choice = input("\nVocê deseja exibir apenas pacotes com comunicações únicas ou todos os pacotes? (1 - Uniques, 2 - Todos): ")
        if choice == '1':
            return True  # Only unique communication pairs
        elif choice == '2':
            return False  # All packets
        else:
            print("Opção inválida. Digite '1' para pacotes únicos ou '2' para todos os pacotes.")



def manipulate_pcap(file_name):
    print(f"Manipulando pacotes no arquivo: {file_name}")

    # Use PcapReader instead of rdpcap
    packets = []  # You can still collect packets in a list if needed, but use PcapReader
    with scapy.PcapReader(file_name) as reader:
        for packet in reader:
            packets.append(packet)  
            

    # Get user choice for displaying packets
    display_unique = get_display_preference()

    # Initialize communication_pairs as a set or list depending on the user's choice
    if display_unique:
        communication_pairs = set()  # Use a set for unique communication pairs
    else:
        communication_pairs = []  # Use a list for all communication pairs (including duplicates)

    # Collect communication pairs from packets
    for packet in packets:
        if packet.haslayer(scapy.IP) and packet.haslayer(scapy.Ether):
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst
            src_mac = packet[scapy.Ether].src
            dst_mac = packet[scapy.Ether].dst

            if display_unique:
                communication_pairs.add((src_ip, dst_ip, src_mac, dst_mac))
            else:
                communication_pairs.append((src_ip, dst_ip, src_mac, dst_mac))
    
    # Get user modifications for communication pairs
    modifications = get_user_modifications(communication_pairs, packets)

    # Process packets with modifications using ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = []
        for packet in packets:
            for (src_ip, dst_ip, src_mac, dst_mac), (new_src_ip, new_dst_ip, new_src_mac, new_dst_mac) in modifications.items():
                futures.append(executor.submit(manipulate_packet, packet, modifications, (src_ip, dst_ip, src_mac, dst_mac)))
        
        # Wait for all futures to complete
        for future in futures:
            future.result()

    # Save the modified packets back to a new file
    output_file = f"modified_{os.path.basename(file_name)}"
    scapy.wrpcap(output_file, packets)
    print(f"Pacotes modificados salvos em: {output_file}")


# Main function to run the menu
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