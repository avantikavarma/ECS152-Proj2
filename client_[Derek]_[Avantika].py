import socket
import json

SERVER_IP = "127.0.0.1" # currently SERVER_IP is NOT set to a value in the blocklist
PROXY_IP = "127.0.0.1"
CLIENT_IP = "127.0.0.1"
SERVER_PORT = 2000
PROXY_PORT = 2001
CLIENT_PORT = 2002

IP_BLOCKLIST = ["127.0.0.2", "127.0.0.3", "127.0.0.4", "127.0.0.5", "127.0.0.6", "127.0.0.7"]

def client():
    # get the 4 char message
    message = input()
    data_out = {"server_ip": SERVER_IP,
                "server_port": SERVER_PORT,
                "message": message}
    print("----------------------------\nSent to Proxy:\n----------------------------")
    print("data = ", data_out)

    # conver to JSON
    data_out_JSON = json.dumps(data_out)
    data_out_b = data_out_JSON.encode("utf-8")

    # open connection to proxy
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # send data
        s.connect((PROXY_IP, PROXY_PORT))
        s.sendall(data_out_b)
        
        # recieve data
        data_in_b = s.recv(4096)
        data_in = data_in_b.decode("utf-8")
        print("----------------------------\nReceived from Proxy:\n----------------------------")
        print("\"" + data_in + "\"")
        s.close()
        
    return

client()