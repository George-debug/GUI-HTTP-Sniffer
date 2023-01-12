from sniffer.packages.HypertextTransferProtocol import HypertextTransferProtocol
from typing import Callable
from typing import List, Dict


def all_bytes_are_null(data: bytes) -> bool:
    """
    Checks if all bytes are null. Useful to check for a "keep alive packet"

    Args:
        data (bytes): The data to be checked

    Returns:
        bool: True if all bytes are null, False otherwise
    """
    for byte in data:
        if byte != 0:
            return False
    return True


class SessionInfo:
    """
    Holds the value of a tcp session. It is used to identify a session becuase it can be hashed and stored in a Dictionary

    Attributes:
        source_address (str): The source address of the session found in the IP layer
        destination_address (str): The destination address of the session found in the IP layer
        source_port (int): The source port of the session found in the TCP layer
        destination_port (int): The destination port of the session found in the TCP layer
    """

    def __init__(self, packet: HypertextTransferProtocol) -> None:
        """
        It creates a SessionInfo object by converting from a HypertextTransferProtocol packet

        Args:
            packet (HypertextTransferProtocol): The packet to be converted
        """
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


def is_fin(packet: HypertextTransferProtocol) -> bool:
    """
    Checks if the packet is a FIN packet by checking the flags of the TCP layer

    Args:
        packet (HypertextTransferProtocol): The packet to be checked

    Returns:
        bool: True if the packet is a FIN packet, False otherwise
    """
    return packet.tcp_layer.flags & 0b000001


def is_syn(packet: HypertextTransferProtocol) -> bool:
    """
    Checks if the packet is a SYN packet by checking the flags of the TCP layer

    Args:
        packet (HypertextTransferProtocol): The packet to be checked

    Returns:
        bool: True if the packet is a SYN packet, False otherwise
    """
    return packet.tcp_layer.flags & 0b000010


def is_empty(packet: HypertextTransferProtocol) -> bool:
    """
    Checks if the packet is a empty packet by checking if the data has only null bytes

    Args:
        packet (HypertextTransferProtocol): The packet to be checked

    Returns:
        bool: True if the packet is a empty packet, False otherwise
    """
    return all_bytes_are_null(packet.data)


def merge_packages(packets: List[HypertextTransferProtocol]) -> bytes:
    """
    Merges all the data into a single bytes object

    Args:
        packets (List[HypertextTransferProtocol]): The packets to be merged, they must be ordered

    Returns:
        bytes: The merged data
    """
    data = b""
    for packet in packets:
        data += packet.data
    return data


class OrderHTTP:
    """
    This class is used to order the packets of a HTTP session. It is used to merge the data of the packets into a single bytes object

    Attributes:
        __packets (Dict[SessionInfo, List[HypertextTransferProtocol]]): A dictionary that holds the packets of each session
        __callback (Callable[[bytes], None]): The callback to be called when a HTTP session is completed
    """

    def __init__(self, callback: Callable[[bytes], None]) -> None:
        """
        It creates a OrderHTTP object, it takes a callback that is called when a HTTP session is completed

        Args:
            callback (Callable[[bytes], None]): The callback to be called when a HTTP session is completed
        """
        self.__packets: Dict[SessionInfo, List[HypertextTransferProtocol]] = {}
        self.__callback = callback

    def __search_through_packets(self, packets: List[HypertextTransferProtocol], i: int = 0) -> List[HypertextTransferProtocol] or int:
        """
        It searches through the packets to find the first SYN packet and then it checks if the packets are ordered.
        If they are ordered it returns the packets, otherwise it returns the index of the first packet that is not ordered

        Args:
            packets (List[HypertextTransferProtocol]): The packets to be searched
            i (int, optional): The index to start the search. Defaults to 0.
        """
        while i < len(packets):
            if is_syn(packets[i]):
                break
            i += 1

        if i == len(packets):
            return i

        returned_packets = []

        while i < len(packets) - 1:
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
        """
        It gets the ordered packets of a session, if the packets are not ordered it returns None,
        otherwise it returns the ordered packets and deletes them from the dictionary

        Args:
            packet (HypertextTransferProtocol): The packet to be checked

        Returns:
            List[HypertextTransferProtocol] or None: The ordered packets or None if the packets are not ordered
        """
        key = SessionInfo(packet)
        if key not in self.__packets:
            return None
        packets = self.__packets[key]
        packets.sort(key=lambda x: x.tcp_layer.sequence_number)

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
        """
        It is called when a packet is received, it orders the packets and calls the callback when a HTTP session is completed

        Args:
            packet (HypertextTransferProtocol): The packet to be checked
        """
        if not (is_fin(packet) or is_syn(packet)) and is_empty(packet):
            # keep alive packet
            return
        key = SessionInfo(packet)
        if key not in self.__packets:
            self.__packets[key] = []
        self.__packets[key].append(packet)

        packets = self.__get_order(packet)

        if packets is not None:
            self.__callback(merge_packages(packets))
