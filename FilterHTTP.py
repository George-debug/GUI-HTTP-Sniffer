import threading
from datetime import datetime
from typing import Callable
from typing import List

ignored_headers = ["Method", "Path", "Version"]


class HTTPPRequest:
    def __init__(self, bytes):
        headers = {}
        lines = bytes.split(b'\r\n')

        title = lines[0].split(b' ')

        if len(title) != 3:
            raise Exception("Invalid HTTP request")
        # print("good")
        method, path, version = title

        if method not in [b"GET", b"POST", b"PUT", b"DELETE"]:
            raise Exception("Invalid HTTP request")

        headers["Method"] = method.decode()
        headers["Path"] = path.decode()
        headers["Version"] = version.decode()
        lines = lines[1:]
        for line_index in range(len(lines)):
            line = lines[line_index]
            if len(line) == 0:
                self.body = b'\r\n'.join(lines[line_index + 1:])
                break

            key, value = line.split(b': ')
            headers[key.decode()] = value.decode()

        self.headers = headers

    def __str__(self) -> str:
        rv = f"Method: {self.headers['Method']}\r\n"
        rv += f"Path: {self.headers['Path']}\r\n"
        rv += f"Version: {self.headers['Version']}\r\n\r\n"

        for key in self.headers:
            if key in ignored_headers:
                continue
            rv += f"{key}: {self.headers[key]}\r\n"

        rv += "\r\nBody:\r\n"
        rv += self.body.decode("utf-8", errors="ignore")

        return rv

    def __repr__(self) -> str:
        return self.__str__()


def get_current_time() -> int:
    curr_dt = datetime.now()
    return int(round(curr_dt.timestamp()))


class FilterHTTP:
    def __init__(self):
        self.__packets: List[HTTPPRequest] = []
        self.__filters: List[Callable[[HTTPPRequest], bool]] = []
        # self.__lock = threading.Lock()

    def add_packet(self, packet: bytes):
        # print("adding packet")
        try:
            request = HTTPPRequest(packet)
            for filter in self.__filters:
                if not filter(request):
                    return
            self.__packets.append(request)
        except Exception as e:
            # print("Error: " + str(e))
            pass

    def clear(self):
        self.__packets.clear()

    def remove_filters(self):
        self.__filters.clear()

    def next(self) -> HTTPPRequest:
        if len(self.__packets) == 0:
            return None

        return self.__packets.pop(0)

    def add_contains_filter(self, key: str, value: str):
        def filter(request: HTTPPRequest) -> bool:
            return key in request.headers and value in request.headers[key]

        self.__filters.append(filter)

    def add_equals_filter(self, key: str, value: str):
        def filter(request: HTTPPRequest) -> bool:
            return key in request.headers and request.headers[key] == value

        self.__filters.append(filter)
