import socket,os
import threading
from typing import Callable, Literal

MatchStrategy = Literal["exact", "startswith", "endswith", "contains"]

class Route:
    def __init__(self, path: str, function: Callable, matching: MatchStrategy = "exact"):
        self.path = path
        if not self.path.startswith("/"):
            self.path = "/" + path
        self.function = function
        self.matching = matching

    def matches(self, input_path: str) -> bool:
        '''Check if a path matches the defined route'''
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
    '''Build a response'''
    if content != "" and content_type != "":
        end = f"Content-Type: {content_type}\r\n\r\n{content}\n"
    elif content != "":
        end = f"Content-Type: text/plain\r\n\r\n{content}\n"
    else:
        end = ""
    return f"HTTP/1.1 {status}\r\n{end}".encode()

def rls(x: str):
    '''Remove left spaces'''
    for idx, i in enumerate(x):
        if i != " ": break
    return x[idx:]

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

            if data["method"] == "POST" and "body" not in data.keys():
                buffer = connection.recv(1024)
                data["body"] = self.parse_body(buffer, data["headers"]["content-type"])

            found = False

            for i in self.bound_paths:
                if i.matches(data["path"]):
                    i.call(connection,data)
                    found = True
                    break

            if not found and self.fileshare:
                try:
                    if os.path.exists("."+data["path"]):
                        content_type = "text/plain"
                        match data["path"].split(".")[-1]:
                            case "html": content_type = "text/html"
                            case "md": content_type = "text/markdown"
                            case "css": content_type = "text/css"
                            case "js": content_type = "text/javascript"
                        connection.send(response(content_type = content_type, content = open("."+data["path"],'r').read()))
                        found = True
                except Exception as e:
                    print(f"Error opening {data['path']}: {e}")

            if not found:
                connection.send(response("404 NOT FOUND", content="404 not found"))

            connection.close()

    def parse_request(self,buffer: bytes):
        state = "status"
        headers = {}
        body = None
        for idx, i in enumerate(buffer.decode().split("\r\n")):
            match state:
                case "status":
                    method, path, version = i.split(" ")
                    state = "headers"
                case "headers":
                    if i == "":
                        state = "body"
                        continue
                    colon_split = i.split(":")
                    headers[rls(colon_split[0].lower())] = rls(":".join(colon_split[1:]))
                case "body":
                    if i == "":
                        break
                    body = self.parse_body(("\r\n".join(buffer.decode().split("\r\n")[idx:])).encode(),headers["content-type"])

        data = {'method':method, 'path':path, 'version':version, 'headers':headers}
        if body != None:
            data["body"] = body
        return data

    def parse_body(self, buffer: bytes, content_type: str):
        body = {}

        match content_type:
            case "application/x-www-form-urlencoded":
                for i in buffer.decode().split("&"):
                    key = i.split("=")[0]
                    value = "=".join(i.split("=")[1:])
                    body[key] = value

        return body
