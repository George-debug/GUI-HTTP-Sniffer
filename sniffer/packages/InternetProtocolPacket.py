import struct


def bytes_to_ip_address(bytes_addr) -> str:
    """
    Converts bytes to ip address string

    Args:
        bytes_addr (bytes): The bytes to be converted

    Returns:
        str: The bytes converted to ip address string
    """
    bytes_str = map(str, bytes_addr)
    ip_addr = '.'.join(bytes_str)
    return ip_addr


class InternetProtocolPacket:
    """
        Unpacks the raw data of the IP header, and stores the data in the attributes.

        Attributes:
            data (bytes): The raw data of the remaining packet
            version (int): The version of the IP header
            header_length (int): The length of the IP header
            type_of_service (int): The type of service of the IP header
            total_length (int): The total length of the IP header
            identification (int): The identification of the IP header
            flags (int): The flags of the IP header
            fragment_offset (int): The fragment offset of the IP header
            time_to_live (int): The time to live of the IP header
            ip_protocol (int): The ip protocol of the IP header
            header_checksum (int): The header checksum of the IP header
            source_address (str): The source address of the IP header
            destination_address (str): The destination address of the IP header
            unhandled_ip_header (bytes): The unhandled data of the IP header
    """

    def __unpack_ip_header(self):
        """
        It unpacks the raw data of the IP header, and stores the data in the attributes.

        Raises:
            Exception: If the version of the IP header is not 4
        """
        # unpack IP header

        # B - unsigned char (1 byte)
        # H - unsigned short (2 bytes)
        # I - unsigned int (4 bytes)

        (version_and_header_length,
            self.type_of_service,
            self.total_length,
            self.identification,
            flags_and_fragment_offset,
            self.time_to_live,
            self.ip_protocol,
            self.header_checksum,
            source_address,
            destination_address) = struct.unpack("! B B H H H B B H 4s 4s", self.data[:20])

        # version is first 4 bits of version_and_header_length
        # vvvvhhhh >> 4 = vvvv
        self.version = version_and_header_length >> 4

        if self.version != 4:
            raise Exception("Not IPv4 packet")

        # header length is last 4 bits of version_and_header_length
        # vvvvhhhh & 00001111 = hhhh
        self.header_length = version_and_header_length & 15

        # flags are first 3 bits of flags_and_fragment_offset
        # fffooooo oooooooo >> 13  = fff
        self.flags = flags_and_fragment_offset >> 13

        # fragment offset is last 13 bits of flags_and_fragment_offset
        # fffooooo oooooooo & 0001111111111111 = 000ooooo oooooooo
        self.fragment_offset = flags_and_fragment_offset & 8191

        # TODO: i dont know how to handle this and i dont think i need to
        self.unhandled_ip_header = self.data[20:self.header_length * 4]

        self.source_address = bytes_to_ip_address(source_address)
        self.destination_address = bytes_to_ip_address(destination_address)

        # data is the rest of the packet
        self.data = self.data[self.header_length * 4:]

    def __init__(self, data: bytes):
        """
        It unpacks the raw data of the IP header, and stores the data in the attributes.

        Args:
            data (bytes): The raw data of the remaining packet

        Raises:
            Exception: If the version of the IP header is not 4
        """
        self.data = data

        self.__unpack_ip_header()

    @classmethod
    def is_this_packet(cls, data: bytes):
        """
        It checks if the data is an IP packet

        Args:
            data (bytes): The data representing ethernet frame

        Returns:
            bool: True if the data is an IP packet, False otherwise
        """

        ethernet_type = struct.unpack("! H", data[12:14])[0]

        return ethernet_type == 0x0800
