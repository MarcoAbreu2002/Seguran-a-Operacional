from scapy.all import *
from pyDNP3.opendnp3 import *

def parse_pcap_dnp3(pcap_file):
    packets = rdpcap(pcap_file)
    parser = DataDecoder()

    for packet in packets:
        if IP in packet and UDP in packet:
            # Check for DNP3 port numbers (adjust as needed)
            if packet[UDP].sport == 20000 or packet[UDP].dport == 20000:
                # Parse the DNP3 message
                message = Message()
                parser.fromString(bytes(packet[UDP].payload), message)

                # Extract information from the DNP3 message
                for index in range(message.objects.count()):
                    obj = message.getObject(index)
                    object_type = obj.getDescriptor().getType()
                    value = obj.getValue().toString()
                    timestamp = message.getTimestamp()

                    # Write information to a text file
                    with open('dnp3_data.txt', 'a') as f:
                        f.write(f"Object Type: {object_type}, Value: {value}, Timestamp: {timestamp}\n")

# Example usage:
parse_pcap_dnp3('DNP3_Dataset.pcap')
