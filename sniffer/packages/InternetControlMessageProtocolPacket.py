from sniffer.packages.InternetProtocolPacket import InternetProtocolPacket
import struct


class InternetControlMessageProtocolPacket:
    """
    It converts a Internet Protocol Packet into a Internet Control Message Protocol Packet
    """

    def __unpack_icmp_header(self):
        """
        It unpacks the ICMP header and stores the data in the attributes
        """
        # unpack ICMP header
        # B - unsigned char (1 byte)
        # H - unsigned short (2 bytes)
        # I - unsigned int (4 bytes)
        (self.type,
         self.code,
         self.checksum,
         self.extended_header) = struct.unpack(
            "! B B H 4s", self.ip_layer.data[:8])

        self.data = self.ip_layer.data[8:]

        # delete ip_layer data
        self.ip_layer.data = None

    def __init__(self, packet: InternetProtocolPacket) -> None:
        self.ip_layer = packet
        self.__unpack_icmp_header()

    @classmethod
    def is_this_packet(cls, packet: InternetProtocolPacket) -> bool:
        """
        It checks if the IP packet is a ICMP packet

        Args:
            packet (InternetProtocolPacket): The IP packet

        Returns:
            bool: True if the IP packet is a ICMP packet, False otherwise
        """
        return packet.ip_protocol == 1

    def __str__(self) -> str:
        return f"ICMP: {self.ip_layer.source_address} -> {self.ip_layer.destination_address} | data_length: {len(self.data)}"

    __repr__ = __str__
