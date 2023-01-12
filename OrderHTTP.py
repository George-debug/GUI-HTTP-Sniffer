from sniffer.packages.HypertextTransferProtocol import HypertextTransferProtocol


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


class SequenceOrderer:
    def __init__(self) -> None:
        self.


class OrderHTTP:
    def __init__(self) -> None:
        self.sessions = {}

    def __call__(self, packet: HypertextTransferProtocol) -> None:
        session = SessionInfo(packet)
        if session not in self.sessions:
            self.sessions[session] = []

        self.sessions[session].append(packet)
