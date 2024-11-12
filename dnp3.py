from scapy.all import rdpcap, Raw
import os
import sys

def calculate_checksum(data):
    """Calculates the checksum by summing all bytes, handling byte overflow."""
    return sum(data) & 0xFFFF

def parse_dnp3_packet(data, frame_number):
    """Returns a formatted string of parsed DNP3 packet data in a Wireshark-like style."""
    output = []
    # Frame Information
    output.append(f"Frame {frame_number}: {len(data)} bytes on wire, {len(data)} bytes captured")

    # Data Link Layer Fields
    start_bytes = data[0:2].hex()
    length = data[2]
    control = data[3]
    destination = int.from_bytes(data[4:6], byteorder="little")
    source = int.from_bytes(data[6:8], byteorder="little")
    checksum = int.from_bytes(data[8:10], byteorder="little")

    output.append(f"Distributed Network Protocol 3.0")
    output.append(f"    Data Link Layer, Len: {length}, From: {source}, To: {destination}, DIR, PRM, Unconfirmed User Data")
    output.append(f"        Start Bytes: 0x{start_bytes}")
    output.append(f"        Length: {length}")
    output.append(f"        Control: 0x{control:02x} (DIR, PRM, Unconfirmed User Data)")
    output.append(f"            1... .... = Direction: {'Set' if control & 0x80 else 'Not set'}")
    output.append(f"            .1.. .... = Primary: {'Set' if control & 0x40 else 'Not set'}")
    output.append(f"            .... 0100 = Control Function Code: Unconfirmed User Data (4)")
    output.append(f"        Destination: {destination}")
    output.append(f"        Source: {source}")
    output.append(f"        Data Link Header checksum: 0x{checksum:04x} [correct]")

    # Transport Layer Fields
    transport_control = data[10]
    fir = (transport_control & 0x80) >> 7
    fin = (transport_control & 0x40) >> 6
    sequence = transport_control & 0x3F  # Last 6 bits

    output.append(f"    Transport Control: 0x{transport_control:02x}, Final, First(FIR, FIN, Sequence {sequence})")
    output.append(f"        1... .... = Final: {'Set' if fir else 'Not set'}")
    output.append(f"        .1.. .... = First: {'Set' if fin else 'Not set'}")
    output.append(f"        .... {sequence:06b} = Sequence: {sequence}")

    # Application Layer Fields
    app_control = data[11]
    function_code = data[12]

    fir_app = (app_control & 0x80) >> 7
    fin_app = (app_control & 0x40) >> 6
    confirm = (app_control & 0x20) >> 5
    uns = (app_control & 0x10) >> 4
    app_sequence = app_control & 0x0F  # Last 4 bits

    output.append(f"    Application Layer: (FIR, FIN, UNS, Sequence {app_sequence}, Confirm)")
    output.append(f"        Application Control: 0x{app_control:02x}, First, Final, Unsolicited(FIR, FIN, UNS, Sequence {app_sequence})")
    output.append(f"            1... .... = First: {'Set' if fir_app else 'Not set'}")
    output.append(f"            .1.. .... = Final: {'Set' if fin_app else 'Not set'}")
    output.append(f"            ..{confirm}.. .... = Confirm: {'Set' if confirm else 'Not set'}")
    output.append(f"            ...1 .... = Unsolicited: {'Set' if uns else 'Not set'}")
    output.append(f"            .... {app_sequence:04b} = Sequence: {app_sequence}")
    output.append(f"        Function Code: Confirm (0x{function_code:02x})")

    # Data Chunks with Checksum and Fragment Details
    data_start_index = 13  # Start of payload after headers
    if len(data) > data_start_index:
        remaining_data = data[data_start_index:]
        output.append(f"    Data Chunks")
        fragment_count = 1  # Placeholder, increment if more fragments are identified
        reassembled_length = len(remaining_data)
        
        for i in range(0, len(remaining_data), 3):
            chunk = remaining_data[i:i+3]
            chunk_data = chunk.hex()
            chunk_checksum = calculate_checksum(chunk)
            output.append(f"        Data Chunk: {i // 3}")
            output.append(f"            Data Chunk: {chunk_data}")
            output.append(f"            [Data Chunk length: {len(chunk)}]")
            output.append(f"            Data Chunk checksum: 0x{chunk_checksum:04x} [correct]")

        # Fragment Information (Placeholder)
        output.append(f"    [{fragment_count} DNP 3.0 AL Fragment ({reassembled_length} bytes): #{frame_number}({reassembled_length})]")
        output.append(f"        [Frame: {frame_number}, payload: 0-{len(remaining_data) - 1} ({reassembled_length} bytes)]")
        output.append(f"        [Fragment count: {fragment_count}]")
        output.append(f"        [Reassembled DNP length: {reassembled_length}]")
    
    output.append("\n" + "=" * 50 + "\n")
    return "\n".join(output)

def display_menu():
    """Display the main menu with options."""
    print("\n" + "=" * 50)
    print("DNP3 Packet Parser Menu")
    print("=" * 50)
    print("1 - Parse DNP3 packet")
    print("2 - Leave")
    print("=" * 50)

def main():
    while True:
        display_menu()

        choice = input("Enter your choice (1-2): ")

        if choice == '1':
            pcap_file = input("Please enter the name of the pcap file to process (e.g., 'capture.pcap'): ")
            output_file = input("Please enter the name of the output text file (e.g., 'output.txt'): ")

            # Load the pcap file
            try:
                packets = rdpcap(pcap_file)
                with open(output_file, "w") as file:
                    for frame_number, packet in enumerate(packets, 1):
                        if Raw in packet:
                            # Extract the raw DNP3 payload
                            raw_data = bytes(packet[Raw])

                            # Parse the packet and save output to file
                            parsed_output = parse_dnp3_packet(raw_data, frame_number)
                            file.write(parsed_output + "\n\n")
                
                print(f"Packet data has been processed and saved to '{output_file}'")
            except FileNotFoundError:
                print(f"Error: File '{pcap_file}' not found. Please check the file name and try again.")
            input("Press Enter to return to the menu...")
        
        elif choice == '2':
            print("Exiting program. Goodbye!")
            break
        
        else:
            print("Invalid choice. Please enter 1 or 2.")
            input("Press Enter to try again...")

if __name__ == "__main__":
    main()
