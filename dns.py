#!/usr/bin/env python3
"""
DNS Client - Resolves IP address for a domain from scratch using socket API.
No high-level DNS libraries used. Manual DNS packet construction and parsing.
"""

import socket
import struct
import time
import random
import sys 

# Using root servers from the assignment link 
ROOT_SERVERS = [
    "198.41.0.4",      # a.root-servers.net ... Verisign, Inc.
    "170.247.170.2",   # b.root-servers.net ... USC Information Sciences Institute
    "192.33.4.12",     # c.root-servers.net .....Cogent Communications
    "199.7.91.13",     # d.root-servers.net  .....University of Maryland
    "192.203.230.10",  # e.root-servers.net ...NASA (Ames Research Center)
    "192.5.5.241",     # f.root-servers.net... Internet Systems Consortium, Inc.
    "192.112.36.4",    # g.root-servers.net.....US Department of Defense (NIC)
    "198.97.190.53",   # h.root-servers.net  .. US Army (Research Lab)
    "192.36.148.17",   # i.root-servers.net  .... Netnod
    "192.58.128.30",   # j.root-servers.net  .....Verisign, Inc.
    "193.0.14.129",    # k.root-servers.net..RIPE NCC
    "199.7.83.42",     # l.root-servers.net......ICANN
    "202.12.27.33",    # m.root-servers.net  ..... WIDE Project
]

DOMAIN = "microsoft.com"
DNS_PORT = 53   # dns always uses port 53 apparently 
TIMEOUT = 10

# DNS Record Types
RECORD_TYPES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    15: "MX",
    28: "AAAA",
    41: "OPT",
}

#build the dns packet 
def build_dns_query(domain, qtype=1):
    "building the dns query packet from scratch."
    transaction_id = random.randint(0, 65535)   #dns is 16 bit 
    flags = 0x0100  # standard query
    flags = 0x0000  # don't want recursion 
    qdcount = 1
    ancount = 0
    nscount = 0
    arcount = 0

    # 12 byte DNS header 
    header = struct.pack(">HHHHHH",
                         transaction_id,
                         flags,
                         qdcount,
                         ancount,
                         nscount,
                         arcount)

    # Encode QNAME
    qname = b""
    for label in domain.split("."): #split at the . 
        encoded = label.encode("ascii")
        qname += struct.pack("B", len(encoded)) + encoded
    qname += b"\x00"  # convert to bytes 

    # QTYPE= 1(A), QCLASS=IN(1) which is internet class 
    question = qname + struct.pack(">HH", qtype, 1) 

    return header + question, transaction_id    #return packet 

#data is dns response, offset is where the name starts 
def parse_name(data, offset):
    labels = []
    jumped = False
    max_jumps = 10
    jumps = 0
    original_offset = offset

    while True:
        if offset >= len(data):
            break
        length = data[offset]

        #end of name 
        if length == 0: 
            offset += 1
            break
        elif (length & 0xC0) == 0xC0:
            # if first 2 bits are 11 its a pointer 
            if offset + 1 >= len(data):
                break
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                original_offset = offset + 2
            offset = pointer
            jumped = True
            jumps += 1
            if jumps > max_jumps:
                break
        else:
            offset += 1
            labels.append(data[offset:offset + length].decode("ascii", errors="replace"))
            offset += length

    if jumped:
        return ".".join(labels), original_offset
    return ".".join(labels), offset


def parse_dns_response(data):
    #take raw udp response 
    #unpack header ..read first 12 bytes and parse through 
    if len(data) < 12:
        return None

    #parse answer, authority

    tid, flags, qdcount, ancount, nscount, arcount = struct.unpack(">HHHHHH", data[:12])
    offset = 12

    # Skip question section
    for _ in range(qdcount):
        _, offset = parse_name(data, offset)
        offset += 4  # QTYPE + QCLASS

    records = []


    #Resource record .. [Name] [Type] [Class] [ttl] [rdlength] [rdata]

    def parse_rr_section(count):
        nonlocal offset     # keeps track of where we are in the dns packt 
        for i in range(count):
            if offset >= len(data):     #stop if reached the end of the packet 
                break 
            name, offset = parse_name(data, offset)

            #each resource header will be 10 bytes else stop parsing
            if offset + 10 > len(data):
                break
            rtype, rclass, ttl, rdlength = struct.unpack(">HHIH", data[offset:offset + 10])

            # move past the header 
            offset += 10

            #move to next record 
            rdata = data[offset:offset + rdlength]
            offset += rdlength

            record = parse_rdata(rtype, rdata, data, offset - rdlength)
            records.append((rtype, name, record))

    parse_rr_section(ancount)    # Answer reocrds
    parse_rr_section(nscount)    # Authority records 
    parse_rr_section(arcount)    # Additional records 

    #store values as a list 
    return {
        "tid": tid,
        "flags": flags,
        "ancount": ancount,
        "nscount": nscount,
        "arcount": arcount,
        "records": records,
    }


def parse_rdata(rtype, rdata, full_data, rdata_start):
    "Parse record data based on type"
    if rtype == 1:  # A type
        if len(rdata) == 4: #IPv4
            return socket.inet_ntoa(rdata)
    elif rtype == 28:  # AAAA type (IPv6)
        if len(rdata) == 16:
            return socket.inet_ntop(socket.AF_INET6, rdata)
    elif rtype in (2, 5, 12):  # NS, CNAME, PTR ....domain names 
        name, _ = parse_name(full_data, rdata_start)
        return name
    elif rtype == 15:  # MX ( pref + mail server host name)
        if len(rdata) >= 2:
            preference = struct.unpack(">H", rdata[:2])[0]
            exchange, _ = parse_name(full_data, rdata_start + 2)
            return f"{preference} {exchange}"
    elif rtype == 6:  # SOA ( primary nameserver and email )
        mname, next_off = parse_name(full_data, rdata_start)
        rname, _ = parse_name(full_data, next_off)
        return f"{mname} {rname}"
    #return unknown data as hexadecimals 
    return rdata.hex()


def send_dns_query(server_ip, domain, qtype=1):
    "Send DNS query to server, return (response, rtt_ms)"

    #call dns packet constructor function 
    query, tid = build_dns_query(domain, qtype)

    #create udp socket 
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    #timeout 
    sock.settimeout(TIMEOUT)

    try:
        #measuring how long the request will take 
        start = time.time()
        sock.sendto(query, (server_ip, DNS_PORT))   #send query 
        response_data, _ = sock.recvfrom(4096)  #get dns response 
        rtt = (time.time() - start) * 1000  #request time 
        return parse_dns_response(response_data), rtt
    except socket.timeout:
        return None, None
    finally:
        sock.close()


def get_record_type_name(rtype):
    return RECORD_TYPES.get(rtype, f"TYPE{rtype}")


def print_separator():
    print("--------------------------------------------")


def resolve_iterative(domain):
    "resolve domain starting from root servers iteratively"
    current_servers = list(ROOT_SERVERS)
    queried_server = current_servers[0]
    final_ip = None

    # Try each root server
    for root_ip in ROOT_SERVERS:
        response, rtt = send_dns_query(root_ip, domain)
        if response is not None:
            current_servers = [root_ip]
            break

    # Iterative resolution loop
    server_to_query = ROOT_SERVERS[0]

    # track which server visited 
    visited = set()

    while True:
        if server_to_query in visited:
            break
        visited.add(server_to_query)

        print_separator()
        print(f"Querying {server_to_query} for {domain}")
        print_separator()

        response, rtt = send_dns_query(server_to_query, domain)

        # Try fallback servers if timeout
        if response is None:
            found = False
            for alt in ROOT_SERVERS:
                if alt != server_to_query:
                    response, rtt = send_dns_query(alt, domain)
                    if response is not None:
                        found = True
                        break
            if not found:
                print(f"No response from {server_to_query}")
                break

        records = response["records"]

        # Print all records
        a_records = []
        ns_records = []
        cname_records = []
        aaaa_records = []
        other_records = []

        for rtype, name, value in records:
            if rtype == 41:  # Skip OPT
                continue
            type_name = get_record_type_name(rtype)
            if value is None:
                continue
            print(f"{type_name} : {value}")
            if rtype == 1:
                a_records.append(value)
            elif rtype == 2:
                ns_records.append(value)
            elif rtype == 5:
                cname_records.append(value)
            elif rtype == 28:
                aaaa_records.append(value)

        print(f"RTT: {rtt:.2f} ms")

        # If we have A records in answer section -> done
        # Check if answer section has A records (ancount > 0)
        answer_a = []
        answer_cname = []
        for rtype, name, value in records[:response["ancount"]]:
            if rtype == 1:
                answer_a.append(value)
            elif rtype == 5:
                answer_cname.append(value)

        if answer_a:
            final_ip = answer_a[0]
            break

        # Follow CNAME if present
        if answer_cname:
            domain = answer_cname[0]
            server_to_query = ROOT_SERVERS[0]
            visited.clear()
            continue

        # Look for glue A records for NS servers
        # Collect NS names and glue records
        ns_names = []
        glue_ips = {}

        for rtype, name, value in records:
            if rtype == 2:
                ns_names.append(value)

        # Glue records are A records in additional section (after answer+authority)
        authority_end = response["ancount"] + response["nscount"]
        for rtype, name, value in records[authority_end:]:
            if rtype == 1:
                glue_ips[name] = value

        # Find a glue IP for one of the NS records
        next_server = None
        for ns in ns_names:
            if ns in glue_ips:
                next_server = glue_ips[ns]
                break

        if next_server is None and ns_names:
            # Need to resolve NS hostname - use a root server
            # Try to resolve ns hostname using a working resolver
            for ns in ns_names:
                for root in ROOT_SERVERS:
                    ns_response, _ = send_dns_query(root, ns)
                    if ns_response:
                        for rtype, name, value in ns_response["records"]:
                            if rtype == 1:
                                next_server = value
                                break
                    if next_server:
                        break
                if next_server:
                    break

        if next_server:
            server_to_query = next_server
        else:
            print("Could not find next server to query.")
            break

    return final_ip


#HTTP Request
def make_http_request(ip, domain):
    "Make an HTTP request to the resolved IP."
    print_separator()
    print(f"Making HTTP request to {ip}")
    print_separator()

    #create TCP socket 
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)

    try:
        #record time
        start = time.time()
        sock.connect((ip, 80))  #connect to server 

        #build http request 
        http_request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {domain}\r\n"
            f"Connection: close\r\n"
            f"User-Agent: DNS-Client/1.0\r\n"
            f"\r\n"
        )
        sock.sendall(http_request.encode("ascii"))

        response = b""
        while True:
            try:
                chunk = sock.recv(4096)
                # loop stops when server stops sending data 
                if not chunk:   
                    break
                response += chunk

                #if headers are fully recieved - end marked by that sequence  
                if b"\r\n\r\n" in response:
                    break
            except socket.timeout:
                break

        rtt = (time.time() - start) * 1000

        # Extract status line
        status_line = response.split(b"\r\n")[0].decode("ascii", errors="replace")
        # Get status code
        parts = status_line.split(" ")
        if len(parts) >= 2:
            status_code = parts[1]
        else:
            status_code = status_line

        print(status_code)
        print(f"RTT: {rtt:.2f} ms")

    except Exception as e:
        print(f"HTTP request failed: {e}")

    # close socket 
    finally:
        sock.close()


def main():
    if len(sys.argv) != 2:
        print("Usage: python dns_client.py <domain>")
        sys.exit(1)


    # take command line argument 
    domain = sys.argv[1]

    final_ip = resolve_iterative(domain)

    if final_ip:
        make_http_request(final_ip, domain)
    else:
        print("Failed to resolve domain.")


if __name__ == "__main__":
    main()
