import pyshark

# Function to safely convert values to integers, handling invalid literals
def safe_int(value, base=16):
    try:
        return int(value, base)
    except ValueError:
        return None

# Function to extract and write detailed DNP3 data to a text file
def extract_dnp3_data(packet, file):
    try:
        # Check if the packet contains TCP on port 20000 (DNP3)
        if 'TCP' in packet and (packet['TCP'].dstport == '20000' or packet['TCP'].srcport == '20000'):
            file.write(f"\nDNP3 Packet Found at {packet.sniff_time}\n")
            
            # Extract Ethernet information
            eth_src = packet.eth.src if 'eth' in packet else 'N/A'
            eth_dst = packet.eth.dst if 'eth' in packet else 'N/A'
            file.write(f"Ethernet: Src: {eth_src}, Dst: {eth_dst}\n")
            
            # Extract IP layer information
            if 'IP' in packet:
                ip_src = packet.ip.src
                ip_dst = packet.ip.dst
                file.write(f"IP: Src: {ip_src}, Dst: {ip_dst}\n")
            
            # Extract TCP layer information
            if 'TCP' in packet:
                tcp_src_port = packet.tcp.srcport
                tcp_dst_port = packet.tcp.dstport
                tcp_seq = packet.tcp.seq
                tcp_ack = packet.tcp.ack
                file.write(f"TCP: Src Port: {tcp_src_port}, Dst Port: {tcp_dst_port}, Seq: {tcp_seq}, Ack: {tcp_ack}\n")
            
            # Check if the packet contains DNP3 data
            if 'dnp3' in packet:
                # Extract DNP3 Data Link Layer (DLP)
                dnp3_control = packet.dnp3.control if hasattr(packet.dnp3, 'control') else 'N/A'
                dnp3_dest = packet.dnp3.destination if hasattr(packet.dnp3, 'destination') else 'N/A'
                dnp3_src = packet.dnp3.source if hasattr(packet.dnp3, 'source') else 'N/A'
                dnp3_length = packet.dnp3.length if hasattr(packet.dnp3, 'length') else 'N/A'
                file.write(f"DNP3 Data Link Layer: Control: {dnp3_control}, Src: {dnp3_src}, Dst: {dnp3_dest}, Length: {dnp3_length}\n")
                
                # Safely convert DNP3 control field
                control_int = safe_int(dnp3_control)
                if control_int is not None:
                    dnp3_direction = 'Set' if (control_int & 0x80) else 'Clear'
                    dnp3_primary = 'Primary' if (control_int & 0x40) else 'Secondary'
                    dnp3_function_code = control_int & 0x0F
                    file.write(f"DNP3 Direction: {dnp3_direction}, Primary: {dnp3_primary}, Control Function Code: {dnp3_function_code}\n")
                else:
                    file.write(f"DNP3 Control (Invalid or Missing): {dnp3_control}\n")
                
                # DNP3 Data Link Layer Checksum
                if hasattr(packet.dnp3, 'checksum'):
                    dnp3_checksum = packet.dnp3.checksum
                    file.write(f"DNP3 Checksum: {dnp3_checksum}\n")
                
                # DNP3 Transport Layer information (if available)
                if hasattr(packet.dnp3, 'transport'):
                    transport_info = packet.dnp3.transport
                    if transport_info:
                        transport_control = transport_info.control if hasattr(transport_info, 'control') else 'N/A'
                        transport_sequence = transport_info.sequence if hasattr(transport_info, 'sequence') else 'N/A'
                        transport_first = "Yes" if "First" in transport_control else "No"
                        transport_final = "Yes" if "Final" in transport_control else "No"
                        file.write(f"Transport Control: {transport_control}, Sequence: {transport_sequence}, First: {transport_first}, Final: {transport_final}\n")
                
                # DNP3 Application Layer (FIR, FIN, UNS, Sequence)
                if hasattr(packet.dnp3, 'application_control'):
                    app_control = packet.dnp3.application_control
                    app_function_code = packet.dnp3.function_code if hasattr(packet.dnp3, 'function_code') else 'N/A'
                    app_sequence = packet.dnp3.sequence if hasattr(packet.dnp3, 'sequence') else 'N/A'
                    app_unsolicited = 'Yes' if "Unsolicited" in app_control else 'No'
                    app_confirm = 'Yes' if "Confirm" in app_control else 'No'
                    file.write(f"Application Layer: Control: {app_control}, Function Code: {app_function_code}, Sequence: {app_sequence}, Unsolicited: {app_unsolicited}, Confirm: {app_confirm}\n")
                    
                    # Handle specific Function Codes (example: Confirm, Read, Write)
                    if app_function_code == '0x00':
                        file.write("Function Code: Confirm\n")
                    elif app_function_code == '0x01':
                        file.write("Function Code: Read\n")
                    elif app_function_code == '0x02':
                        file.write("Function Code: Write\n")
                    elif app_function_code == '0x03':
                        file.write("Function Code: Write - Data\n")
                    
                    # Optionally extract data depending on function code
                    if hasattr(packet.dnp3, 'data'):
                        data = packet.dnp3.data
                        file.write(f"Data: {data}\n")
                    
                    # Check for Time Stamp in application layer
                    if hasattr(packet.dnp3, 'timestamp'):
                        timestamp = packet.dnp3.timestamp
                        file.write(f"Timestamp: {timestamp}\n")
                    
                    # Additional Application Layer Information
                    if hasattr(packet.dnp3, 'error_check'):
                        error_check = packet.dnp3.error_check
                        file.write(f"Error Check: {error_check}\n")
                
            else:
                file.write("No DNP3 data found in this packet.\n")
            
    except AttributeError as e:
        file.write(f"Error processing packet (AttributeError): {e}\n")
    except Exception as e:
        file.write(f"Error processing packet: {e}\n")

# Function to analyze the pcap file and output DNP3 data to a txt file
def analyze_pcap(pcap_file, output_file):
    cap = pyshark.FileCapture(pcap_file, display_filter="tcp.port == 20000")
    
    with open(output_file, 'w') as file:
        for packet in cap:
            extract_dnp3_data(packet, file)

# Sample usage
pcap_file = 'DNP3_Dataset.pcap'  # Replace with the path to your pcap file
output_file = 'dnp3_output_complete.txt'  # Replace with the desired output file name
analyze_pcap(pcap_file, output_file)
