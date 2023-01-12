import struct


def get_mac_address(mac_address: bytes) -> str:
    return ':'.join(map('{:02x}'.format, mac_address))


class AddressResolutionProtocolPacket:
    """
        Represents the ARP packet.

        Attributes:
            hardware_type (int): The hardware type of the ARP packet
            protocol_type (int): The protocol type of the ARP packet
            hardware_length (int): The hardware length of the ARP packet
            protocol_length (int): The protocol length of the ARP packet
            opcode (int): The opcode of the ARP packet
            sender_hardware_address (str): The sender hardware address of the ARP packet
            sender_protocol_address (str): The sender protocol address of the ARP packet
            target_hardware_address (str): The target hardware address of the ARP packet
    """

    def __unpack_arp_header(self):
        """
        Unpacks the raw data of the ARP header, and stores the data in the attributes.
        """
        (self.hardware_type,
         self.protocol_type,
         self.hardware_length,
         self.protocol_length,
         self.opcode,
         self.sender_hardware_address,
         self.sender_protocol_address,
         self.target_hardware_address,
         self.target_protocol_address) = struct.unpack('! H H B B H 6s 4s 6s 4s', self.data[:28])

        self.data = self.data[28:]

    def __init__(self, packet: bytes):
        self.__unpack_arp_header(packet)

    @classmethod
    def is_this_packet(cls, packet: bytes):
        """
        Checks if the packet is an ARP packet.

        Args:
            packet (bytes): The ethernet packet to be checked

        Returns:
            bool: True if the packet is an ARP packet, False otherwise
        """

        ethernet_type = struct.unpack("! H", packet[12:14])[0]
        return ethernet_type == 0x0806

    def __str__(self):
        return f"ARP: {self.sender_hardware_address} -> {self.target_hardware_address} | data_length: {len(self.data)}"

    __repr__ = __str__
