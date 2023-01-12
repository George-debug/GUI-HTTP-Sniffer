from sniffer.packages.TransmissionControlProtocolPacket import TransmissionControlProtocolPacket

# TODO: add Packet to the name


def toHex(data: bytes) -> str:
    """
    Converts bytes to hex

    It was used for testing

    Args:
        data (bytes): The data to be converted

    Returns:
        str: The data converted to hex
    """
    return ' '.join([hex(x) for x in data])


class HypertextTransferProtocol:

    """
    It converts a Transmission Control Protocol Packet into a Hyper Text Transfer Protocol Packet

    It can check if the TCO packet is a HTTP packet

    Attributes:
        tcp_layer (TransmissionControlProtocolPacket): The TCP packet
        data (bytes): The unhandled data of the HTTP packet
    """

    def __init__(self, packet: TransmissionControlProtocolPacket) -> None:
        """
        It converts a Transmission Control Protocol Packet into a Hyper Text Transfer Protocol Packet

        Args:
            packet (TransmissionControlProtocolPacket): The TCP packet
        """
        self.tcp_layer = packet

        self.data = self.tcp_layer.data
        self.tcp_layer.data = None

    @ classmethod
    def is_this_packet(cls, packet: TransmissionControlProtocolPacket) -> bool:
        """
        Checks if the TCP packet is a HTTP packet

        Args:
            packet (TransmissionControlProtocolPacket): The TCP packet

        Returns:
            bool: True if the TCP packet is a HTTP packet, False otherwise
        """
        return packet.source_port == 80 or packet.destination_port == 80
