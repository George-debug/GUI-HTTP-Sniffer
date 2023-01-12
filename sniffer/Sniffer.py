import socket
from sniffer.packages.InternetProtocolPacket import InternetProtocolPacket
from typing import Callable


class Sniffer:
    """
    It captures the all the packets from the eth0 network. At the moment only Linux implementation is available.
    """

    def __init__(self, handle_packet: Callable[[InternetProtocolPacket], None]):
        """
        Args:
            handle_packet (Callable[[InternetProtocolPacket], None]): A function that will be called when a packet is captured.
        """
        self._handle_packet = handle_packet
        self.__is_running = False

    def start(self):
        """
        Starts the sniffer, blocking the current thread
        """
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
        """
        This function is called every time a packet is captured. It will ignore the Ethernet header,
        convert It to InternetProtocolPacket and pass the rest of the packet to the handle_packet function.
        """

        if not self.__is_running:
            return

        try:
            packet = InternetProtocolPacket(raw_data[14:])

            self._handle_packet(packet)
        except:
            pass

    def stop(self):
        """
        Stops the sniffer
        """
        self.__is_running = False
