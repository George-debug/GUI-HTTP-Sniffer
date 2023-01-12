from sniffer.packages.TransmissionControlProtocolPacket import TransmissionControlProtocolPacket
import socket


def toHex(data: bytes) -> str:
    return ' '.join([hex(x) for x in data])


class HypertextTransferProtocol:

    def unpack_http_header(self):
        lines = self.tcp_layer.data.split(b'\r\n')
        headers = {}

        headers["Method"], headers["Path"], headers["Version"] = lines[0].split(
            b' ')

        lines = lines[1:]

        for line in lines:
            if len(line) == 0:
                break

            key, value = line.split(b': ')
            headers[key.decode()] = value.decode()

        self.headers = headers

    def __init__(self, packet: TransmissionControlProtocolPacket) -> None:
        self.tcp_layer = packet

        self.unpack_http_header()

    @ classmethod
    def is_this_packet(cls, packet: TransmissionControlProtocolPacket) -> bool:
        # try:
        #     serv = socket.getservbyport(port, "tcp")
        #     return serv == "http"
        # except:
        #     return False
        if len(packet.data) < 2:
            return False
        return packet.source_port == 80 or packet.destination_port == 80
