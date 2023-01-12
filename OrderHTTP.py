from sniffer.packages.HypertextTransferProtocol import HypertextTransferProtocol
import threading
from typing import Callable
from typing import List, Tuple, Dict


def all_bytes_are_null(data: bytes) -> bool:
    for byte in data:
        if byte != 0:
            return False
    return True


class SessionInfo:
    def __init__(self, packet: HypertextTransferProtocol) -> None:
        self.source_address = packet.tcp_layer.ip_layer.source_address
        self.destination_address = packet.tcp_layer.ip_layer.destination_address
        self.source_port = packet.tcp_layer.source_port
        self.destination_port = packet.tcp_layer.destination_port

    def __hash__(self) -> int:
        return hash((self.source_address, self.destination_address, self.source_port, self.destination_port))

    def __eq__(self, o: object) -> bool:
        if not isinstance(o, SessionInfo):
            return False
        return (
            self.source_address == o.source_address
            and self.destination_address == o.destination_address
            and self.source_port == o.source_port
            and self.destination_port == o.destination_port
        )


class SequenceOrderer:
    def __init__(self, callback: Callable[[bytes], None]) -> None:
        self.packets: List[HypertextTransferProtocol] = []
        self.lock = threading.Lock()
        self.fin = False
        self.syn = False
        self.callback = callback

    def __order(self) -> bool:
        self.packets.sort(key=lambda x: x.tcp_layer.sequence_number)

        # checking if no data is missing
        for i in range(len(self.packets)-1):
            current_packet = self.packets[i]
            next_packet = self.packets[i+1]
            if len(current_packet.data) + current_packet.tcp_layer.sequence_number != next_packet.tcp_layer.sequence_number:
                return False
        return True

    def __call__(self, packet: HypertextTransferProtocol) -> None:
        with self.lock:
            if packet.tcp_layer.flags & 0b000001:
                self.fin = True
                print("FIN")
            if packet.tcp_layer.flags & 0b000010:
                self.syn = True
                print("SYN")
            if packet.tcp_layer.flags & 0b000100:
                self.callback(None)
                return

            if not all_bytes_are_null(packet.data):
                self.packets.append(packet)

            if self.syn and self.fin and self.__order():
                data = b""
                for packet in self.packets:
                    data += packet.data
                self.callback(data)


class OrderHTTP:
    def __init__(self, callback) -> None:
        self.sessions = {}
        self.__callback = callback

    def __call__(self, packet: HypertextTransferProtocol) -> None:
        session = SessionInfo(packet)
        if session not in self.sessions:
            # callback = remove session from self.sessions and use self.__callback
            def callback(data: bytes) -> None:
                self.sessions.pop(session)
                self.__callback(data)

            self.sessions[session] = SequenceOrderer(callback)

        self.sessions[session](packet)
