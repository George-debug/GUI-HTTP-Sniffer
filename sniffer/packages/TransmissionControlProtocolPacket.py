import sniffer.packages.InternetProtocolPacket as InternetProtocolPacket
import struct

class TransmissionControlProtocolPacket(InternetProtocolPacket):
    def __unpack_tcp_header(self):
        # print("unpacking tcp header")

        # unpack TCP header

        # B - unsigned char (1 byte)
        # H - unsigned short (2 bytes)
        # I - unsigned int (4 bytes)
        \
            self.source_port, \
            self.destination_port, \
            self.sequence_number, \
            self.acknowledgement_number, \
            self.data_offset, \
            self.reserved, \
            self.flags, \
            self.window_size, \
            self.checksum, \
            self.urgent_pointer \
            = struct.unpack("! H H I I B B H H H", self.data[:20])

        # print("this =>>", struct.unpack("! 20B", self.data[:20]))\

    def __init__(self, data):
        super().__init__(data)
        self.__unpack_tcp_header()