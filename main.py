from sniffer.Sniffer import Sniffer
from sniffer.packages.InternetProtocolPacket import InternetProtocolPacket
from sniffer.packages.TransmissionControlProtocolPacket import TransmissionControlProtocolPacket
from sniffer.packages.HypertextTransferProtocol import HypertextTransferProtocol
from OrderHTTP import OrderHTTP
from FilterHTTP import FilterHTTP
import threading
from typing import Dict, List, Callable

http_filter = FilterHTTP()

orderer = OrderHTTP(http_filter.add_packet)


def on_packet(packet: InternetProtocolPacket):
    """
    It is called when a packet is captured. It checks if the packet is a HTTP packet and if it is, it adds it to the filter

    Args:
        packet (InternetProtocolPacket): The packet to be checked
    """
    try:
        if TransmissionControlProtocolPacket.is_this_packet(packet):
            tcp_packet = TransmissionControlProtocolPacket(packet)
            if HypertextTransferProtocol.is_this_packet(tcp_packet):
                http_packet = HypertextTransferProtocol(tcp_packet)
                orderer(http_packet)
    except:
        pass


s = Sniffer(on_packet)

sniffer_thread = threading.Thread(target=s.start)
sniffer_thread.start()


def clear_command(args: List[str]):
    """
    Command: clear
    It clears the list of packets.

    Args:
        args (List[str]): The arguments of the command
    """
    if len(args) != 0:
        print("Invalid arguments")
        return
    http_filter.clear()


def next_command(args: List[str]):
    """
    Command: next
    It returns the next packet in the list of packets

    Args:
        args (List[str]): The arguments of the command
    """
    if len(args) != 0:
        print("Invalid arguments")
        return
    request = http_filter.next()
    if request is None:
        print("No more requests")
        return
    print(request)


def add_filter_command(args: List[str]):
    """
    Command: add_filter <<contains/equals>> <<key>> <<value>>
    It adds a filter to the list of filters

    Args:
        args (List[str]): The arguments of the command
    """

    contains_equal = args[0]
    args = args[1:]

    if len(args) != 2:
        print("Invalid arguments")
        return

    if contains_equal == "contains":
        http_filter.add_contains_filter(args[0], args[1])
    elif contains_equal == "equals":
        http_filter.add_equals_filter(args[0], args[1])

    http_filter.clear()

    print("Filter added")


def exit_command(args: List[str]):
    """
    Command: exit
    It stops the sniffer and exits the program

    Args:
        args (List[str]): The arguments of the command
    """
    if len(args) != 0:
        print("Invalid arguments")
        return

    s.stop()
    sniffer_thread.join()
    exit(0)


def remove_filters_command(args: List[str]):
    """
    Command: remove_filters
    It removes all the filters

    Args:
        args (List[str]): The arguments of the command
    """
    if len(args) != 0:
        print("Invalid arguments")
        return

    http_filter.remove_filters()


# Dict that contains all the commands
COMMANDS: Dict[str, Callable[[List[str]], None]] = {
    "clear": clear_command,
    "next": next_command,
    "add_filter": add_filter_command,
    "exit": exit_command,
    "remove_filters": remove_filters_command
}

while True:
    command = input("Enter command: ")
    command = command.split(" ")
    if command[0] not in COMMANDS:
        print("Invalid command")
        continue
    COMMANDS[command[0]](command[1:])
