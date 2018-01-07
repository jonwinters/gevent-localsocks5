import sys
import os
import signal
import struct
import gevent

from enum import Enum, unique

assert gevent.version_info > (1, 0, 0, 0), "Need gevent 1.0.0+"

from gevent import sleep, spawn, spawn_later
from gevent import socket
from gevent.server import StreamServer
from gevent.socket import gethostbyname
from socketpool import ConnectionPool, TcpConnector

import logging

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(msg)s")
logger = logging.getLogger(__file__)
log = logger.debug


@unique
class AddressType(Enum):
    IPV4 = 1
    URL = 3


def handle_tcp(fr, to):
    try:
        while to.send(fr.recv(4096)) > 0:
            continue
    except socket.error:
        pass


class Socks5Server(StreamServer):
    HOSTCACHE = {}
    HOSTCACHETIME = 1800

    def __init__(self, *args, **kw):
        super(Socks5Server, self).__init__(*args, **kw)
        self.remote_pool = ConnectionPool(factory=TcpConnector,
                                          max_size=600,
                                          max_lifetime=3,
                                          backend="gevent")

        def log_tcp_pool_size(s):
            log("ConnPool size: %d" % self.remote_pool.size)
            spawn_later(10, s, s)

        def log_dns_pool_size(s):
            log("DNSPool size: %d" % len(self.HOSTCACHE))
            spawn_later(10, s, s)

        spawn_later(10, log_tcp_pool_size, log_tcp_pool_size)
        spawn_later(10, log_dns_pool_size, log_dns_pool_size)

    def close(self):
        self.remote_pool.release_all()
        super(Socks5Server, self).close()

    def handle(self, sock, address):
        sock_file = sock.makefile('rb', -1)
        remote = None
        try:
            log('socks connection from ' + str(address))
            # 1. 设置handle超时
            sock.settimeout(10)
            sock.recv(262)
            sock.send(b"\x05\x00")
            # 2. 收到请求
            data = sock_file.read(4)
            decode_data = data.decode(encoding='ascii')
            mode = ord(decode_data[1])
            address_type = ord(decode_data[3])
            remote_address, port = self.get_remote_address_port(address_type, sock_file)
            if mode == 1:  # 1. 创建tcp连接
                self.create_remote_connection_pipe(remote_address, port, sock)
            else:
                reply = b"\x05\x07\x00\x01"  # 不支持的命令
                sock.send(reply)
                raise socket.error
        except socket.error:
            pass
        finally:
            if remote is not None:
                self.remote_pool.release_connection(remote)
            log("Close handle")
            sock_file.close()
            sock.close()

    def create_remote_connection_pipe(self, address, port, sock):
        """
        :param address: 远程地址
        :param port: 远程端口
        :param sock: 本地连接的sock
        :return:
        """
        remote = None
        try:
            remote = self.remote_pool.get(host=address, port=port)
            if self.remote_pool.too_old(remote):
                self.remote_pool.release_connection(remote)
                remote = self.remote_pool.get(host=address, port=port)
            reply = b"\x05\x00\x00\x01" + socket.inet_aton(address) + \
                    struct.pack(">H", port)
            sock.send(reply)
            log('Begin data, %s:%s' % (address, port))
            # 3.  协程监听sock读写
            l1 = spawn(handle_tcp, sock, remote)
            l2 = spawn(handle_tcp, remote, sock)
            gevent.joinall((l1, l2))
        except socket.error as error:
            log('Conn refused, %s:%s' % (address, port))
            # Connection refused
            reply = b'\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00'
            sock.send(reply)
            raise error
        finally:
            if remote is not None:
                self.remote_pool.release_connection(remote)

    def get_remote_address_port(self, address_type, sock_file):
        address = None
        if address_type == AddressType.IPV4.value:  # ipv4地址
            address = socket.inet_ntoa(sock_file.read(4))
        elif address_type == AddressType.URL.value:  # 域名
            domain_length = ord(decode(sock_file.read(1)))
            domain = decode(sock_file.read(domain_length))
            address = self.handle_dns(domain)
        if address is None:
            raise ValueError('地址错误')
        port = struct.unpack('>H', sock_file.read(2))[0]
        return address, port

    def handle_dns(self, domain):

        if domain not in self.HOSTCACHE:
            log('Resolving ' + domain)
            addr = gethostbyname(domain)
            self.HOSTCACHE[domain] = addr
            spawn_later(self.HOSTCACHETIME,
                        lambda a: self.HOSTCACHE.pop(a, None), domain)
        else:
            addr = self.HOSTCACHE[domain]
            log('Hit resolv %s -> %s in cache' % (domain, addr))

        return addr


def main():
    try:
        listen = (sys.argv[1], int(sys.argv[2]))
    except ValueError:
        print("usage: host port ")

    server = Socks5Server(listen)

    def kill():
        logger.info("kill triggered")
        server.close()
        spawn(lambda: (sleep(2) is os.closerange(3, 1024)))

    gevent.signal(signal.SIGTERM, kill)
    gevent.signal(signal.SIGQUIT, kill)
    gevent.signal(signal.SIGINT, kill)
    server.start()
    logger.info("Listening at %s" % str(listen))
    gevent.wait()


def decode(b):
    """
    :param b: bytes
    :return: decode by ascii encode
    """
    if isinstance(b, bytes):
        return b.decode(encoding='ascii')
    else:
        return ''


if __name__ == "__main__":
    main()
