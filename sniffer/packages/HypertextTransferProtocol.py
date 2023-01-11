from sniffer.packages.TransmissionControlProtocolPacket import TransmissionControlProtocolPacket
import socket


def toHex(data: bytes) -> str:
    return ' '.join([hex(x) for x in data])


class HypertextTransferProtocol:

    def unpack_http_header(self):
        print(len(self.tcp_layer.data))
        if len(self.tcp_layer.data) < 2:
            return

        print(toHex(self.tcp_layer.data))
        lines = self.tcp_layer.data.split(b'\r\n')
        print("lines: ", lines)
        headers = {}
        body = b''
        header_end = False
        for line in lines:
            if not header_end:
                if line:
                    header, value = line.split(b':')
                    headers[header.decode()] = value.decode().strip()
                else:
                    header_end = True
            else:
                body += line

        print("headers: ", headers)
        print("body: ", body)

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
        return packet.source_port == 80 or packet.destination_port == 80
