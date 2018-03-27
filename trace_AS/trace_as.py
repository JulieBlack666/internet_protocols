import argparse
import socket
from json import loads
from urllib.request import urlopen


def trace(destination_ip, hops, timeout):
    echo_request = b'\x08\x00\x0b\x27\xeb\xd8\x01\x00'
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    sock.settimeout(timeout)
    ttl = 1
    curr_ip = None
    while curr_ip != destination_ip and ttl != hops:
        sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
        sock.sendto(echo_request, (destination_ip, 1))
        try:
            ip = sock.recvfrom(1024)[1]
            curr_ip = ip[0]
            message = f'{ttl}. {curr_ip: <20}'
            message += get_info(curr_ip)
            print(message)
        except socket.timeout:
            print(f'{ttl}. *** Timeout exceeded')
        ttl += 1


def get_info(ip):
    info = loads(urlopen(f'http://ipinfo.io/{ip}/json').read())
    if 'bogon' in info:
        return ''
    keys = ['country', 'region', 'city', 'org']
    return ', '.join([info[key] for key in keys if info[key]])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='AS tracer')
    parser.add_argument('destination', type=str, help='Destination ip or host name')
    parser.add_argument('--hops', '-hops', default=30, type=int, help='Maximum amount of hops')
    parser.add_argument('--timeout', '-t', default=5, type=int, help='Connection timeout')
    args = parser.parse_args()
    trace(socket.gethostbyname(args.destination), args.hops, args.timeout)
