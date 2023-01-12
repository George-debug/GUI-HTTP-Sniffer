from typing import Callable
from typing import List


class HTTPPRequest:
    def __init__(self, bytes):
        headers = {}
        lines = bytes.split(b'\r\n')

        title = lines[0].split(b' ')

        if len(title) != 3:
            raise Exception("Invalid HTTP request")

        headers["Method"], headers["Path"], headers["Version"] = title
        lines = lines[1:]
        for line in lines:
            if len(line) == 0:
                break

            key, value = line.split(b': ')
            headers[key.decode()] = value.decode()

        self.headers = headers


class FilterHTTP:
    def __init__(self):
        self.__packets: List[HTTPPRequest] = []

    def add_packet(self, packet: bytes):
        try:
            self.__packets.append(HTTPPRequest(packet))
        except:
            pass
