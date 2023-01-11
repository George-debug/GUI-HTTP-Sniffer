from sniffer.Sniffer import Sniffer
from sniffer.packages.InternetProtocolPacket import InternetProtocolPacket
from sniffer.packages.TransmissionControlProtocolPacket import TransmissionControlProtocolPacket
from sniffer.packages.HypertextTransferProtocol import HypertextTransferProtocol


destination_set = set()


def print_destination(packet: InternetProtocolPacket):
    if packet.destination_address not in destination_set:
        destination_set.add(packet.destination_address)
        print(packet.destination_address)


def print_all(packet: InternetProtocolPacket):
    print("===============================================")
    print(packet.source_address, " -> ",
          packet.destination_address, packet.ip_protocol)


def piped(packet: InternetProtocolPacket):
    if not TransmissionControlProtocolPacket.is_this_packet(packet):
        return
    tcp_packet = TransmissionControlProtocolPacket(packet)

    if not HypertextTransferProtocol.is_this_packet(tcp_packet):
        return

    http_packet = HypertextTransferProtocol(tcp_packet)

    print("IS HTTP PACKET")


s = Sniffer(piped)
s.start()
