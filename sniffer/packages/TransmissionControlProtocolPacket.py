from sniffer.packages.InternetProtocolPacket import InternetProtocolPacket
import struct


class TransmissionControlProtocolPacket:

    def __unpack_tcp_header(self):
        # print("unpacking tcp header")

        # unpack TCP header

        # B - unsigned char (1 byte)
        # H - unsigned short (2 bytes)
        # I - unsigned int (4 bytes)
        self.source_port, \
            self.destination_port, \
            self.sequence_number, \
            self.acknowledgement_number, \
            data_offset_reserved, \
            self.flags, \
            self.window_size, \
            self.checksum, \
            self.urgent_pointer = struct.unpack(
                "! H H I I B B H H H", self.ip_layer.data[:20])

        # take first half
        self.data_offset = data_offset_reserved >> 4

        # take second half
        self.reserved = data_offset_reserved & 15

        self.data = self.ip_layer.data[self.data_offset * 4:]

        # delete ip_layer data
        self.ip_layer.data = None

        # print("this =>>", struct.unpack("! 20B", self.data[:20]))\

    def __init__(self, packet: InternetProtocolPacket):
        self.ip_layer = packet
        self.__unpack_tcp_header()

    @ classmethod
    def is_this_packet(cls, packet: InternetProtocolPacket):
        return packet.ip_protocol == 6
