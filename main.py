import scapy.all as scapy
import os
import ipaddress
import re
from concurrent.futures import ThreadPoolExecutor

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

def get_user_modifications(communication_pairs):
    modifications = {}
    for src_ip, dst_ip, src_mac, dst_mac in communication_pairs:
        print(f"\nNova linha de comunicação detectada: {src_ip} -> {dst_ip}")
        new_src_ip = get_user_confirmation(src_ip, "IP de origem")
        new_dst_ip = get_user_confirmation(dst_ip, "IP de destino")
        new_src_mac = get_user_confirmation(src_mac, "MAC de origem")
        new_dst_mac = get_user_confirmation(dst_mac, "MAC de destino")
        
        # Store modifications for this communication line
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

        # Modify packet payload if it has a Raw layer
        if packet.haslayer(scapy.Raw):
            data = bytearray(packet[scapy.Raw].load)
            # Ensure data length is sufficient for manipulation
            if len(data) < 11:
                print("Warning: Packet data too short for expected modification structure.")
                return packet  # Skip modification and return original packet
            data[10] = 0xAA  # Registro 1
            data[11] = 0xBB  # Registro 2
            data[12] = 0xCC  # Registro 3
            packet[scapy.Raw].load = bytes(data)

        # Recalculate checksums
        del packet[scapy.IP].chksum
        if packet.haslayer(scapy.TCP):
            del packet[scapy.TCP].chksum
    return packet

def manipulate_pcap(file_name):
    print(f"Manipulando pacotes no arquivo: {file_name}")
    packets = scapy.rdpcap(file_name)
    
    # Collect all unique communication pairs
    communication_pairs = set()
    for packet in packets:
        if packet.haslayer(scapy.IP) and packet.haslayer(scapy.Ether):
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst
            src_mac = packet[scapy.Ether].src
            dst_mac = packet[scapy.Ether].dst
            communication_pairs.add((src_ip, dst_ip, src_mac, dst_mac))
    
    # Get user-defined modifications for each unique communication pair
    modifications = get_user_modifications(communication_pairs)

    # Prepare packets for multithreading
    num_threads = 4
    chunk_size = len(packets) // num_threads
    chunks = [packets[i:i + chunk_size] for i in range(0, len(packets), chunk_size)]

    def process_chunk(chunk):
        processed_packets = []
        for packet in chunk:
            if packet.haslayer(scapy.IP) and packet.haslayer(scapy.Ether):
                src_ip = packet[scapy.IP].src
                dst_ip = packet[scapy.IP].dst
                src_mac = packet[scapy.Ether].src
                dst_mac = packet[scapy.Ether].dst
                
                original_values = (src_ip, dst_ip, src_mac, dst_mac)
                if original_values in modifications:
                    # Manipulate packet with modifications
                    processed_packets.append(manipulate_packet(packet, modifications, original_values))
                else:
                    processed_packets.append(packet)  # No modification needed
            else:
                processed_packets.append(packet)  # No manipulation needed
        return processed_packets

    # Multithreading to process chunks
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        results = executor.map(process_chunk, chunks)

    # Collect results and save to new pcap file
    manipulated_packets = [pkt for result in results for pkt in result]
    manipulated_file = "manipulated_" + file_name
    scapy.wrpcap(manipulated_file, manipulated_packets)
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
