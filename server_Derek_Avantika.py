import socket

"""
Recieve Ping
Send Pong

OR

Recieve non-Ping.
send non-Ping reversed

Note:
    Server = Port 2000
    Proxy = Port 2001
    Client = Port 2002
"""

SERVER_IP = "127.0.0.1"
PROXY_IP = "127.0.0.1"
CLIENT_IP = "127.0.0.1"
SERVER_PORT = 2000
PROXY_PORT = 2001
CLIENT_PORT = 2002

IP_BLOCKLIST = ["127.0.0.2", "127.0.0.3", "127.0.0.4", "127.0.0.5", "127.0.0.6", "127.0.0.7"]


# Server code
def server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as serv:
        serv.bind((SERVER_IP, SERVER_PORT)) # Bind to socket 2000 -- designated server socket 
        serv.listen() # listen for incoming data
        conn, addr = serv.accept() # accept the incoming package
        with conn: # connection established
            data_in_b = conn.recv(4096) # recieve data from connection
            data_in = data_in_b.decode("utf-8")
            # Ping Pong Logic
            print("----------------------------\nReceived from Proxy:\n----------------------------")
            print('\"' + data_in + '\"')

            print("----------------------------\nSent to Proxy:\n----------------------------")
            if data_in_b == b"Ping":
                print("\"Pong\"")
                conn.sendall(b"Pong")
            elif data_in_b == b"Pong":
                print("\"Ping\"")
                conn.sendall(b"Ping")
            else:
                data_out_b = data_in_b[::-1]
                data_out = data_out_b.decode("utf-8")
                print("\"" + data_out + "\"")
                conn.sendall(data_out_b)
            conn.close() # Close connection
        serv.close()
    return

server()
