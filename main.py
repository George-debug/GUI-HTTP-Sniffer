from sniffer.Sniffer import Sniffer
from sniffer.packages.InternetProtocolPacket import InternetProtocolPacket
from sniffer.packages.TransmissionControlProtocolPacket import TransmissionControlProtocolPacket


destination_set = set()


def print_destination(packet: InternetProtocolPacket):
    if packet.destination_address not in destination_set:
        destination_set.add(packet.destination_address)
        print(packet.destination_address)


def print_all(packet: InternetProtocolPacket):
    print("===============================================")
    print(packet.source_address, " -> ",
          packet.destination_address, packet.ip_protocol)


s = Sniffer(print_all, InternetProtocolPacket)
s.start()
