import socket
import json

"""
Rec in the form:
data = {
"server_ip": "127.0.0.1"
"server_port": 7000
"message": "Ping"
}

Assume that server_ip, server_port is hard coded
extract server_ip annd server_port from data
use to fill fields for s.connect

Client --> Proxy
in JSON format
"""

SERVER_IP = "127.0.0.1"
PROXY_IP = "127.0.0.1"
CLIENT_IP = "127.0.0.1"
SERVER_PORT = 2000
PROXY_PORT = 2001
CLIENT_PORT = 2002

IP_BLOCKLIST = ["127.0.0.2", "127.0.0.3", "127.0.0.4", "127.0.0.5", "127.0.0.6", "127.0.0.7"]

def proxy():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as prox_client:
        # bind and listen
        prox_client.bind((PROXY_IP, PROXY_PORT))
        prox_client.listen()
        conn_client, addr = prox_client.accept()

        with conn_client:
            # recieve and parse the data
            data_in_b_client = conn_client.recv(4096)
            data_in_client = data_in_b_client.decode("utf-8")
            
            print("----------------------------\nReceived from Client:\n----------------------------")
            print("data = " + data_in_client)

            data_in_JSON_client = json.loads(data_in_client)

            data_out_client = data_in_JSON_client["message"]
            
            server_ip = data_in_JSON_client["server_ip"]
            server_port = data_in_JSON_client["server_port"]
            data_out_b_client = data_out_client.encode("utf-8")

            # Check if it's not in the blocklist 
            if server_ip not in IP_BLOCKLIST:
                print("----------------------------\nSent to Server:\n----------------------------")
                print('\"' + data_out_client + '\"')
                
                # if so, open up a new TCP socket so that you can connect to the server
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as prox_server:
                    #send the data to the server 
                    prox_server.connect((server_ip, server_port))
                    prox_server.sendall(data_out_b_client)

                    data_in_b_server = prox_server.recv(4096)
                    data_in_server = data_in_b_server.decode("utf-8")

                    print("----------------------------\nReceived from Server:\n----------------------------")
                    print('\"' + data_in_server + '\"')
                    print("----------------------------\nSent to Client:\n----------------------------")
                    print('\"' + data_in_server + '\"')

                    prox_server.close()
                # send the recieved data to the client
                conn_client.send(data_in_b_server)
            # if the IPs blocked send an error message to the client
            else:
                print("----------------------------\nSent to Client:\n----------------------------")
                print("\"Blocklist Error\"")
                conn_client.send(b"Blocklist Error")
        prox_client.close()
    return

proxy()