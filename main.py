from sniffer.Sniffer import Sniffer
from sniffer.packages.DomainNameSystemProtocolPacket import DomainNameSystemProtocolPacket
from sniffer.packages.InternetProtocolPacket import InternetProtocolPacket
from sniffer.packages.TransmissionControlProtocolPacket import TransmissionControlProtocolPacket
from sniffer.packages.HypertextTransferProtocol import HypertextTransferProtocol
from sniffer.packages.InternetControlMessageProtocolPacket import InternetControlMessageProtocolPacket
from sniffer.packages.UserDatagramProtocolPacket import UserDatagramProtocolPacket
from OrderHTTP import OrderHTTP
from FilterHTTP import FilterHTTP

http_filter = FilterHTTP()

orderer = OrderHTTP(http_filter.add_packet)


def on_packet(packet: InternetProtocolPacket):
    try:
        if TransmissionControlProtocolPacket.is_this_packet(packet):
            tcp_packet = TransmissionControlProtocolPacket(packet)

            if DomainNameSystemProtocolPacket.is_this_packet(tcp_packet):
                print("DNS")
                dns_packet = DomainNameSystemProtocolPacket(tcp_packet)
                print(dns_packet)

        elif InternetControlMessageProtocolPacket.is_this_packet(packet):
            print("ICMP")
            icmp_packet = InternetControlMessageProtocolPacket(packet)
            print(icmp_packet)

        elif UserDatagramProtocolPacket.is_this_packet(packet):
            udp_packet = UserDatagramProtocolPacket(packet)

            if DomainNameSystemProtocolPacket.is_this_packet(udp_packet):
                dns_packet = DomainNameSystemProtocolPacket(udp_packet)
                print(dns_packet)
            else:
                print(udp_packet)

    except Exception as e:
        print(e)
        print(e.with_traceback())


s = Sniffer(on_packet)

s.start()
