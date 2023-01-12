from sniffer.packages.InternetProtocolPacket import InternetProtocolPacket
import struct


class TransmissionControlProtocolPacket:
    """
    It converts a Internet Protocol Packet into a Transmission Control Protocol Packet

    It can check if the IP packet is a TCP packet

    Attributes:
        ip_layer (InternetProtocolPacket): The IP packet
        data (bytes): The unhandled data of the TCP packet
        source_port (int): The source port of the TCP packet
        destination_port (int): The destination port of the TCP packet
        sequence_number (int): The sequence number of the TCP packet
        acknowledgement_number (int): The acknowledgement number of the TCP packet
        data_offset (int): The data offset of the TCP packet
        reserved (int): The reserved of the TCP packet
        flags (int): The flags of the TCP packet
        window_size (int): The window size of the TCP packet
        checksum (int): The checksum of the TCP packet
        urgent_pointer (int): The urgent pointer of the TCP packet
    """

    def __unpack_tcp_header(self):
        """
        It unpacks the TCP header and stores the data in the attributes
        """
        # unpack TCP header

        # B - unsigned char (1 byte)
        # H - unsigned short (2 bytes)
        # I - unsigned int (4 bytes)
        (self.source_port,
         self.destination_port,
         self.sequence_number,
         self.acknowledgement_number,
         data_offset_reserved,
         self.flags,
         self.window_size,
         self.checksum,
         self.urgent_pointer) = struct.unpack(
            "! H H I I B B H H H", self.ip_layer.data[:20])

        # take first half
        self.data_offset = data_offset_reserved >> 4

        # take second half
        self.reserved = data_offset_reserved & 15

        self.data = self.ip_layer.data[self.data_offset * 4:]

        # delete ip_layer data
        self.ip_layer.data = None

    def __init__(self, packet: InternetProtocolPacket):
        """
        It converts a Internet Protocol Packet into a Transmission Control Protocol Packet

        Args:
            packet (InternetProtocolPacket): The IP packet
        """
        self.ip_layer = packet
        self.__unpack_tcp_header()

    @ classmethod
    def is_this_packet(cls, packet: InternetProtocolPacket):
        """
        It checks if the IP packet is a TCP packet

        Args:
            packet (InternetProtocolPacket): The IP packet

        Returns:
            bool: True if the IP packet is a TCP packet, False otherwise
        """
        return packet.ip_protocol == 6
