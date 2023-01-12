import threading
from datetime import datetime
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


def get_current_time() -> int:
    curr_dt = datetime.now()
    return int(round(curr_dt.timestamp()))


class FilterHTTP:
    def __init__(self):
        self.__packets: List[HTTPPRequest] = []
        self.filters: List[Callable[[HTTPPRequest], bool]] = []
        # self.__lock = threading.Lock()

    def add_packet(self, packet: bytes):
        try:
            request = HTTPPRequest(packet)
            for filter in self.filters:
                if not filter(request):
                    return
            self.__packets.append(request)
        except:
            pass

    def clear(self):
        self.__packets.clear()

    def next(self) -> HTTPPRequest:
        if len(self.__packets) == 0:
            return None

        return self.__packets.pop(0)

    def add_contains_filter(self, key: str, value: str):
        def filter(request: HTTPPRequest) -> bool:
            return key in request.headers and value in request.headers[key]

        self.filters.append(filter)

    def add_equals_filter(self, key: str, value: str):
        def filter(request: HTTPPRequest) -> bool:
            return key in request.headers and request.headers[key] == value

        self.filters.append(filter)
