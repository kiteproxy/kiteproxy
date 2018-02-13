import logging
import os
from ping.ping import quiet_ping
import ssl
import socket

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

def check_iran_connectivity():
    next(quiet_ping('217.218.127.127', timeout=5000, count=0))
    next(quiet_ping('2.188.20.21', timeout=5000, count=0))

def check_outside_connectivity():
    next(quiet_ping('4.2.2.4', timeout=5000, count=0))
    next(quiet_ping('74.125.28.100', timeout=5000, count=0))

def check_tls_correctness():
    sock = socket.socket()
    sock.connect(('34.192.156.80', 443))
    try:
      ssl_socket = ssl.SSLSocket(sock, server_hostname="instagram.com")
    except ssl.SSLEOFError:
      print("Your ISP's firewall forcibly closed the connection.")
      return
    ssl_socket.sendall(b"GET / HTTP/1.1\r\nHost: instagram.com\r\nConnection: close\r\n\r\n")
    for line in linesplit(ssl_socket):
        print(line)

    # requests.get(
    #     requests.get('%sname=%s&type=%s' % (GOOGLE_DNS_URL,
    #                                         hostname,
    #                                         ltype),
    #                  headers=headers,
    #                  verify=False)
    # )

# check_iran_connectivity()
# check_outside_connectivity()
check_tls_correctness()