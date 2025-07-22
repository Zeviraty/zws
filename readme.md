# zws (Zev Web Server)

> [!CAUTION]
> ⚠️ Security Warning
> 
> `zws` is a minimal, educational web server. It is not secure and not intended for production use.

## Overview

zws is a web server built with Python's standard library. It is part of my personal ecosystem project and i created it only to use in my projects and learn.

 - ✅ No external dependencies
 - ✅ Easy to understand and extend
 - ⚠️ Not production-ready or secure



## Usage

### starting a server:

```python
from zws import Server

# Create and start the server
server = Server(fileshare=True)  # Enables access to static files in the server's directory
server.start("127.0.0.1", 8080)  # Binds to localhost:8080
```

### bind a Route:

```python
from zws import response

def index_handler(connection, data):
    connection.send(response("200 OK", "Hello, World!", "text/plain"))

server.bind_path("/", index_handler)
```

## Notes

 - You can dynamically bind paths while the server is running.
 - If `fileshare=True`, requests like `/index.html` will attempt to serve that file from the working directory.
 - The `response()` helper builds basic HTTP responses.

This project is part of my ecosystem project [Zeco](https://github.com/Zeviraty/Zeco)
