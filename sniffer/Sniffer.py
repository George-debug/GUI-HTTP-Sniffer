import socket
from sniffer.packages.InternetProtocolPacket import InternetProtocolPacket
from typing import Callable
import struct

# sniff HTTP traffic


class Sniffer:
    def __init__(self, handle_packet: Callable[[InternetProtocolPacket], None]):
        self._handle_packet = handle_packet
        self.__is_running = False

    # =============== windows attempt
    # def start(self):
    #     # https://docs.python.org/3/library/socket.html
    #     # for windows:
    #     # the public network interface
    #     host = socket.gethostbyname(socket.gethostname())

    #     # create a raw socket and bind it to the public interface
    #     conn = socket.socket(
    #         socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    #     # conn.bind((host, 0))
    #     conn.bind(("", 0))

    #     # Include IP headers
    #     conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    #     # receive all packets
    #     conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    #     while True:
    #         raw_data, addr = conn.recvfrom(65535)
    #         self.__handle_data(raw_data)

    def start(self):
        self.__is_running = True
        # https://docs.python.org/3/library/socket.html
        # for linux:
        # create a raw socket and bind it to the public interface
        conn = socket.socket(
            socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

        conn.bind(("eth0", 0))

        while self.__is_running:
            raw_data, addr = conn.recvfrom(65535)
            self.__handle_data(raw_data)

    def __handle_data(self, raw_data: bytes):
        try:
            packet = InternetProtocolPacket(raw_data[14:])

            self._handle_packet(packet)
        except:
            pass

    def stop(self):
        self.__is_running = False
