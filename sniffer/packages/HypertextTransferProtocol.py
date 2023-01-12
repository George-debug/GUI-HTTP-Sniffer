from sniffer.packages.TransmissionControlProtocolPacket import TransmissionControlProtocolPacket
import socket


def toHex(data: bytes) -> str:
    return ' '.join([hex(x) for x in data])


def all_bytes_are_null(data: bytes) -> bool:
    for byte in data:
        if byte != 0:
            return False
    return True


class HypertextTransferProtocol:

    # def unpack_http_header(self):
    #     print(toHex(self.tcp_layer.data))
    #     lines = self.tcp_layer.data.split(b'\r\n')
    #     headers = {}

    #     # headers["Method"], headers["Path"], headers["Version"] = lines[0].split(
    #     #     b' ')
    #     headers["title"] = lines[0]

    #     lines = lines[1:]

    #     for line in lines:
    #         if len(line) == 0:
    #             break

    #         key, value = line.split(b': ')
    #         headers[key.decode()] = value.decode()

    #     self.headers = headers

    def __init__(self, packet: TransmissionControlProtocolPacket) -> None:
        self.tcp_layer = packet

        self.data = self.tcp_layer.data
        self.tcp_layer.data = None

        # self.unpack_http_header()

    @ classmethod
    def is_this_packet(cls, packet: TransmissionControlProtocolPacket) -> bool:
        # try:
        #     serv = socket.getservbyport(port, "tcp")
        #     return serv == "http"
        # except:
        #     return False

        # if all_bytes_are_null(packet.data):
        #     return False

        return packet.source_port == 80 or packet.destination_port == 80
