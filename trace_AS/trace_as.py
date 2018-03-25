import argparse
import socket
from json import loads
from urllib.request import urlopen

PRIVATE_NETS = {
    ('10.0.0.0', '10.255.255.255'),
    ('172.16.0.0', '172.31.255.255'),
    ('192.168.0.0', '192.168.255.255'),
    ('127.0.0.0', '127.255.255.255')}

ECHO_REQUEST = b'\x08\x00\x0b\x27\xeb\xd8\x01\x00'


def trace(destination_ip, hops, timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    sock.settimeout(timeout)
    ttl = 1
    curr_ip = None
    while curr_ip != destination_ip and ttl != hops:
        sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
        sock.sendto(ECHO_REQUEST, (destination_ip, 1))
        try:
            ip = sock.recvfrom(1024)[1]
            curr_ip = ip[0]
            message = f'{ttl}. {curr_ip: <20}'
            if is_public(curr_ip):
                message += get_info(curr_ip)
            print(message)
        except socket.timeout:
            print(f'{ttl}. *** Timeout exceeded')
        ttl += 1


def is_public(ip):
    for private_ip in PRIVATE_NETS:
        if private_ip[0] <= ip <= private_ip[1]:
            return False
    return True


def get_info(ip):
    info = loads(urlopen(f'http://ipinfo.io/{ip}/json').read())
    keys = ['country', 'region', 'city', 'org']
    message = ''
    for key in keys:
        if key in info:
            message += f'{info[key]} '
    return message


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='AS tracer')
    parser.add_argument('destination', type=str, help='Destination ip or host name')
    parser.add_argument('--hops', '-hops', default=30, type=int, help='Maximum amount of hops')
    parser.add_argument('--timeout', '-t', default=5, type=int, help='Connection timeout')
    args = parser.parse_args()
    trace(socket.gethostbyname(args.destination), args.hops, args.timeout)
