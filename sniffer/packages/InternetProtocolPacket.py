import struct
import socket
import sys


def bytes_to_ip_address(bytes_addr) -> str:
    bytes_str = map(str, bytes_addr)
    ip_addr = '.'.join(bytes_str)
    return ip_addr


class InternetProtocolPacket:
    def __unpack_ip_header(self):
        # print("unpacking ip header")

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

        # print("this =>>", struct.unpack("! 20B", self.data[:20]))

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
        # print("unpacked ip header")

    def __init__(self, data: bytes):
        self.data = data
        # print("length after ", len(self.data))

        self.__unpack_ip_header()
        # print("length after x2 ", len(self.data))
