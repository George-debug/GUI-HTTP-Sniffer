from typing import Callable
from typing import List


IGNORED_HEADERS = ["Method", "Path", "Version"]


class HTTPPRequest:
    """
    This class represents a HTTP request

    Attributes:
        headers (Dict[str, str]): A dictionary containing the headers of the request. Also, it contains the method, path and version of the request.
        body (bytes): The body of the request
    """

    def __init__(self, pr_bytes: bytes) -> None:
        """
        It converts TCP payload data into a HTTP request

        Args:
            bytes (bytes): The TCP payload data

        Raises:
            Exception: If the TCP payload data is not a valid HTTP request
        """

        headers = {}
        lines = pr_bytes.split(b'\r\n')

        title = lines[0].split(b' ')

        if len(title) != 3:
            raise Exception("Invalid HTTP request")

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
        """
        It returns a string representation of the HTTP request

        Blueprint:
            Method:
            Path:
            Version:

            <<headers>>

            Body:
            <<body>>

        Returns:
            str: The string representation of the HTTP request
        """
        rv = f"Method: {self.headers['Method']}\r\n"
        rv += f"Path: {self.headers['Path']}\r\n"
        rv += f"Version: {self.headers['Version']}\r\n\r\n"

        for key in self.headers:
            if key in IGNORED_HEADERS:
                continue
            rv += f"{key}: {self.headers[key]}\r\n"

        rv += "\r\nBody:\r\n"
        rv += self.body.decode("utf-8", errors="ignore")

        return rv

    def __repr__(self) -> str:
        """
        __repr__ = __str__
        """
        return self.__str__()


class FilterHTTP:
    def __init__(self):
        self.__packets: List[HTTPPRequest] = []
        self.__filters: List[Callable[[HTTPPRequest], bool]] = []

    def add_packet(self, packet: bytes) -> None:
        """
        It adds a packet to the list of packets ONLY if it passes all the filters

        Args:
            packet (bytes): The packet to add
        """
        try:
            request = HTTPPRequest(packet)
            for filter in self.__filters:
                if not filter(request):
                    return
            self.__packets.append(request)
        except:
            pass

    def clear(self):
        """
        It clears the list of packets
        """
        self.__packets.clear()

    def remove_filters(self):
        """
        It removes all the filters
        """
        self.__filters.clear()

    def next(self) -> HTTPPRequest or None:
        """
        It returns the next packet in the list of packets

        Returns:
            HTTPPRequest or None: The next packet in the list of packets
        """
        if len(self.__packets) == 0:
            return None

        return self.__packets.pop(0)

    def add_contains_filter(self, key: str, value: str) -> None:
        """
        It adds the filter: Header key must contain the value

        Args:
            key (str): The header key
            value (str): The value to search
        """
        def filter(request: HTTPPRequest) -> bool:
            return key in request.headers and value in request.headers[key]

        self.__filters.append(filter)

    def add_equals_filter(self, key: str, value: str) -> None:
        """
        It adds the filter: Header key must be equal to the value

        Args:
            key (str): The header key
            value (str): The value to search
        """
        def filter(request: HTTPPRequest) -> bool:
            return key in request.headers and request.headers[key] == value

        self.__filters.append(filter)
