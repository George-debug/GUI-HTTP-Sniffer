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


# class SequenceOrderer:
#     def __init__(self, callback: Callable[[bytes], None]) -> None:
#         self.packets: List[HypertextTransferProtocol] = []
#         # self.lock = threading.Lock()
#         self.fin = False
#         self.syn = False
#         self.callback = callback

#     def __order(self) -> bool:
#         self.packets.sort(key=lambda x: x.tcp_layer.sequence_number)

#         # checking if no data is missing
#         for i in range(len(self.packets)-1):
#             current_packet = self.packets[i]
#             next_packet = self.packets[i+1]
#             if len(current_packet.data) + current_packet.tcp_layer.sequence_number != next_packet.tcp_layer.sequence_number:
#                 return False
#         return True

#     def __call__(self, packet: HypertextTransferProtocol) -> None:
#         # with self.lock:
#         if packet.tcp_layer.flags & 0b000001:
#             self.fin = True
#             print("FIN")
#         if packet.tcp_layer.flags & 0b000010:
#             self.syn = True
#             print("SYN")
#         if packet.tcp_layer.flags & 0b000100:
#             self.callback(None)
#             return

#         if not all_bytes_are_null(packet.data):
#             self.packets.append(packet)

#         if self.syn and self.fin and self.__order():
#             data = b""
#             for packet in self.packets:
#                 data += packet.data
#             self.callback(data)

def is_fin(packet: HypertextTransferProtocol) -> bool:
    return packet.tcp_layer.flags & 0b000001


def is_syn(packet: HypertextTransferProtocol) -> bool:
    return packet.tcp_layer.flags & 0b000010


def is_empty(packet: HypertextTransferProtocol) -> bool:
    return all_bytes_are_null(packet.data)


class IntWrapper:
    def __init__(self, value):
        self.value = value


def merge_packages(packets: List[HypertextTransferProtocol]) -> bytes:
    data = b""
    for packet in packets:
        data += packet.data
    return data


class OrderHTTP:
    def __init__(self, callback: Callable[[bytes], None]) -> None:
        self.packets: Dict[SessionInfo, List[HypertextTransferProtocol]] = {}
        self.__callback = callback

    def __search_through_packets(self, packets: List[HypertextTransferProtocol], i: int = 0) -> List[HypertextTransferProtocol] or int:
        while i < len(packets):
            if is_syn(packets[i]):
                break
            i += 1

        if i == len(packets):
            return i

        returned_packets = []

        while i < len(packets) - 1:

            # print("i: ", i, " | ", packets[i].tcp_layer.sequence_number, " | ", len(
            #     packets[i].data))

            if is_fin(packets[i]):
                returned_packets.append(packets[i])
                return returned_packets

            length = 1

            if not is_syn(packets[i]):
                length = len(packets[i].data)

            if packets[i].tcp_layer.sequence_number + length != packets[i+1].tcp_layer.sequence_number:
                return i+1

            returned_packets.append(packets[i])
            i += 1

        if is_fin(packets[i]):
            returned_packets.append(packets[i])
            return returned_packets

        return i+1

    def __get_order(self, packet: HypertextTransferProtocol) -> List[HypertextTransferProtocol] or None:
        key = SessionInfo(packet)
        if key not in self.packets:
            return None
        packets = self.packets[key]
        packets.sort(key=lambda x: x.tcp_layer.sequence_number)

        # print("=================================")

        # for packet in packets:
        #     print(packet.tcp_layer.sequence_number, " | ", len(
        #         packet.data), " | is_fin: ", is_fin(packet), " | is_empty: ", is_empty(packet), " | is_syn: ", is_syn(packet))

        # print("=================================")

        i = 0
        while i < len(packets):
            returned_packets = self.__search_through_packets(packets, i)
            if isinstance(returned_packets, int):
                i = returned_packets
            else:
                # removing [i:i+len(returned_packets)] from packets
                del packets[i: i+len(returned_packets)]
                return returned_packets

        return None

    def __call__(self, packet: HypertextTransferProtocol) -> None:
        if not (is_fin(packet) or is_syn(packet)) and is_empty(packet):
            # keep alive packet
            return
        key = SessionInfo(packet)
        if key not in self.packets:
            self.packets[key] = []
        self.packets[key].append(packet)

        packets = self.__get_order(packet)

        if packets is not None:
            self.__callback(merge_packages(packets))
