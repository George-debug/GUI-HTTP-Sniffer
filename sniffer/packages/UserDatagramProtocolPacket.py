from sniffer.packages.InternetProtocolPacket import InternetProtocolPacket
import struct


class UserDatagramProtocolPacket:
    """
    It represents a UDP packet. It can be created from an InternetProtocolPacket

    Attributes:
        ip_layer (InternetProtocolPacket): The IP layer of the UDP packet
        source_port (int): The source port of the session found in the UDP layer
        destination_port (int): The destination port of the session found in the UDP layer
        length (int): The length of the UDP packet
        checksum (int): The checksum of the UDP packet
        data (bytes): The data of the UDP packet
    """

    def __unpack_udp_header(self):
        """
        It unpacks the UDP header and stores the data in the attributes
        """
        (self.source_port,
         self.destination_port,
         self.length,
         self.checksum) = struct.unpack('! H H H H', self.ip_layer.data[:8])

        self.data = self.ip_layer.data[8:]

        self.ip_layer.data = None

    def __init__(self, InternetProtocolPacket: InternetProtocolPacket):
        self.ip_layer = InternetProtocolPacket
        self.__unpack_udp_header()

    @classmethod
    def is_this_packet(cls, packet: InternetProtocolPacket):
        """
        It checks if the packet is a UDP packet

        Args:
            packet (InternetProtocolPacket): The IP packet

        Returns:
            bool: True if the packet is a UDP packet, False otherwise
        """
        return packet.ip_protocol == 17

    def __str__(self):
        return f"UDP {self.ip_layer.source_address}:{self.source_port} -> {self.ip_layer.destination_address}:{self.source_port} | data_length: {len(self.data)}"

    __repr__ = __str__
