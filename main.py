import socket,os
import threading
from typing import Callable, Literal

MatchStrategy = Literal["exact", "startswith", "endswith", "contains"]

class Route:
    def __init__(self, path: str, function: Callable, matching: MatchStrategy = "exact"):
        self.path = path
        self.function = function
        self.matching = matching

    def matches(self, input_path: str) -> bool:
        if self.matching == "exact":
            return input_path == self.path
        elif self.matching == "startswith":
            return input_path.startswith(self.path)
        elif self.matching == "endswith":
            return input_path.endswith(self.path)
        elif self.matching == "contains":
            return self.path in input_path
        else:
            raise ValueError(f"Unknown match type: {self.matching}")

    def call(self,*args, **kwargs):
        return self.function(*args, **kwargs)

def response(status:str = "200 OK", content:str = "", content_type:str = ""):
    if content != "" and content_type != "":
        end = f"Content-Type: {content_type}\r\n\r\n{content}\n"
    elif content != "":
        end = f"Content-Type: text/plain\r\n\r\n{content}\n"
    else:
        end = ""
    return f"HTTP/1.1 {status}\r\n{end}".encode()

class Server():
    def __init__(self, fileshare = False):
        self.bound_paths: list[Route] = []
        self.fileshare = fileshare

    def bind_path(self, path:str, function: Callable, matching: MatchStrategy = "exact"):
        self.bound_paths.append(Route(path, function, matching))

    def start(self, ip:str, port:int):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((ip, port))
        self.sock.listen(5)
        threading.Thread(target=self._listenloop).start()

    def _listenloop(self):
        while True:
            connection,address = self.sock.accept()
            buffer = connection.recv(1024)
            data = self.parse_request(buffer)

            found = False

            for i in self.bound_paths:
                if i.matches(data["path"]):
                    i.call(connection)
                    found = True
                    break

            if not found and self.fileshare:
                try:
                    if os.path.exists("."+data["path"]):
                        content_type = "text/plain"
                        match data["path"].endswith():
                            case ".html": content_type = "text/html"
                            case ".md": content_type = "text/markdown"
                            case ".css": content_type = "text/css"
                            case ".js": content_type = "text/javascript"
                        connection.send(response(content_type = content_type, content = open("."+data["path"],'r').read()))
                        found = True
                except:
                    pass

            if not found:
                connection.send(response("404 NOT FOUND", content="404 not found"))

            connection.close()

    def parse_request(self,buffer: bytes):
        state = "status"
        headers = {}
        for i in buffer.decode().split("\r\n"):
            if i == "":
                return {'method':method, 'path':path, 'version':version, 'headers':headers}
            match state:
                case "status":
                    method, path, version = i.split(" ")
                    state = "headers"
                case "headers":
                    colon_split = i.split(":")
                    headers[colon_split[0]] = ":".join(colon_split[1:])
