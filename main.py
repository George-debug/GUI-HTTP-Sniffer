from sniffer.Sniffer import Sniffer
from sniffer.packages.InternetProtocolPacket import InternetProtocolPacket
from sniffer.packages.TransmissionControlProtocolPacket import TransmissionControlProtocolPacket
from sniffer.packages.HypertextTransferProtocol import HypertextTransferProtocol
from OrderHTTP import OrderHTTP


def print_data(data):
    if data is None:
        return
    converted_utf = data.decode("utf-8", errors="ignore")
    print(converted_utf)


orderer = OrderHTTP(print_data)


def on_packet(packet: InternetProtocolPacket):
    if TransmissionControlProtocolPacket.is_this_packet(packet):
        tcp_packet = TransmissionControlProtocolPacket(packet)
        if HypertextTransferProtocol.is_this_packet(tcp_packet):
            http_packet = HypertextTransferProtocol(tcp_packet)
            orderer(http_packet)


s = Sniffer(on_packet)
s.start()
