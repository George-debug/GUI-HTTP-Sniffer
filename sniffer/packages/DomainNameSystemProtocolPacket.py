from sniffer.packages.UserDatagramProtocolPacket import UserDatagramProtocolPacket
from sniffer.packages.TransmissionControlProtocolPacket import TransmissionControlProtocolPacket


class DomainNameSystemProtocolPacket:
    """
    It converts a User Datagram Protocol Packet or a Transmission Control Protocol Packet into a Domain Name System Protocol Packet

    It can check if the UDP or TCP packet is a DNS packet

    Attributes:
        carrier (UserDatagramProtocol or TransmissionControlProtocolPacket): The UDP or TCP packet
    """

    def __init__(self, carrier: UserDatagramProtocolPacket or TransmissionControlProtocolPacket) -> None:
        self.carrier = carrier

    @classmethod
    def is_this_packet(cls, packet: UserDatagramProtocolPacket or TransmissionControlProtocolPacket) -> bool:
        """
        Checks if the UDP or TCP packet is a DNS packet

        Args:
            packet (UserDatagramProtocol or TransmissionControlProtocolPacket): The UDP or TCP packet

        Returns:
            bool: True if the UDP or TCP packet is a DNS packet, False otherwise
        """
        return packet.source_port == 53 or packet.destination_port == 53

    def __str__(self) -> str:
        carrier = self.carrier
        return f"DNS: {carrier.ip_layer.source_address}:{carrier.source_port} -> {carrier.ip_layer.destination_address}:{carrier.source_port} | data_length: {len(carrier.data)}"

    __repr__ = __str__
