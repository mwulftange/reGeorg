#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import argparse
import urllib3
import re
from threading import Thread
from urlparse import urlparse
from socket import *
from threading import Thread
from time import sleep,time

# Constants
SOCKTIMEOUT = 5
RESENDTIMEOUT = 300
DNS_CACHE_TTL = 300
VER = "\x05"
METHOD = "\x00"
SUCCESS = "\x00"
SOCKFAIL = "\x01"
NETWORKFAIL = "\x02"
HOSTFAIL = "\x04"
REFUSED = "\x05"
TTLEXPIRED = "\x06"
UNSUPPORTCMD = "\x07"
ADDRTYPEUNSPPORT = "\x08"
UNASSIGNED = "\x09"

BASICCHECKSTRING = "Georg says, 'All seems fine'"

# Globals
READBUFSIZE = 1024

# Logging
RESET_SEQ = "\033[0m"
COLOR_SEQ = "\033[1;%dm"
BOLD_SEQ = "\033[1m"

BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE = range(8)

LEVEL = {"INFO": logging.INFO, "DEBUG": logging.DEBUG, }

logLevel = "INFO"

COLORS = {
    'WARNING': YELLOW,
    'INFO': WHITE,
    'DEBUG': BLUE,
    'CRITICAL': YELLOW,
    'ERROR': RED,
    'RED': RED,
    'GREEN': GREEN,
    'YELLOW': YELLOW,
    'BLUE': BLUE,
    'MAGENTA': MAGENTA,
    'CYAN': CYAN,
    'WHITE': WHITE,
}


def formatter_message(message, use_color=True):
    if use_color:
        message = message.replace("$RESET", RESET_SEQ).replace("$BOLD", BOLD_SEQ)
    else:
        message = message.replace("$RESET", "").replace("$BOLD", "")
    return message


class ColoredFormatter(logging.Formatter):
    def __init__(self, msg, use_color=True):
        logging.Formatter.__init__(self, msg)
        self.use_color = use_color

    def format(self, record):
        levelname = record.levelname
        if self.use_color and levelname in COLORS:
            levelname_color = COLOR_SEQ % (30 + COLORS[levelname]) + levelname + RESET_SEQ
            record.levelname = levelname_color
        return logging.Formatter.format(self, record)


class ColoredLogger(logging.Logger):

    def __init__(self, name):
        FORMAT = "[$BOLD%(levelname)-18s$RESET]  %(message)s"
        COLOR_FORMAT = formatter_message(FORMAT, True)
        logging.Logger.__init__(self, name, logLevel)
        if (name == "transfer"):
            COLOR_FORMAT = "\x1b[80D\x1b[1A\x1b[K%s" % COLOR_FORMAT
        color_formatter = ColoredFormatter(COLOR_FORMAT)

        console = logging.StreamHandler()
        console.setFormatter(color_formatter)

        self.addHandler(console)
        return


logging.setLoggerClass(ColoredLogger)
log = logging.getLogger(__name__)
transferLog = logging.getLogger("transfer")
dns_cache = {}


class SocksCmdNotImplemented(Exception):
    pass


class SocksProtocolNotImplemented(Exception):
    pass


class RemoteConnectionFailed(Exception):
    pass


class session(Thread):
    def __init__(self, pSocket, connectString, custom_headers={}):
        Thread.__init__(self)
        self.pSocket = pSocket
        self.conn = None
        self.connectString = connectString
        o = urlparse(connectString)
        try:
            self.httpPort = o.port
        except:
            if o.scheme == "https":
                self.httpPort = 443
            else:
                self.httpPort = 80
        self.httpScheme = o.scheme
        self.httpHost = o.netloc.split(":")[0]
        self.httpPath = o.path
        self.cookies = {}
        self.headers = custom_headers
        httpScheme_kwargs = {}
        if o.scheme == "http":
            self.httpScheme = urllib3.HTTPConnectionPool
        else:
            self.httpScheme = urllib3.HTTPSConnectionPool
            httpScheme_kwargs['cert_reqs'] = 'CERT_NONE'

        self.conn = self.httpScheme(host=self.httpHost, port=self.httpPort, **httpScheme_kwargs)

    def mergeHeaders(self, headers):
        if "Cookie" in self.headers and "Cookie" in headers:
            headers["Cookie"] = "; ".join([headers["Cookie"], self.headers["Cookie"]])
        headers_new = self.headers.copy()
        headers_new.update(headers)
        return headers_new

    def updateCookies(self, cookies):
        new_cookies = dict([c.split(";", 1)[0].split("=", 1) for c in cookies])
        self.cookies.update(new_cookies)

    def getcookies(self):
        return "; ".join(["%s=%s" % (k,v) for (k,v) in self.cookies.iteritems()])

    def parseSocks5(self, sock):
        log.debug("SocksVersion5 detected")
        nmethods = sock.recv(1)
        accepted = False
        for i in xrange(0, ord(nmethods)):
            if sock.recv(1) == METHOD:
                accepted = True
        if accepted:
            sock.sendall(VER + METHOD)
        else:
            sock.sendall(VER + "\xFF")
            return
        ver = sock.recv(1)
        cmd, rsv, atyp = (sock.recv(1), sock.recv(1), sock.recv(1))
        target = None
        targetPort = None
        if atyp == "\x01":  # IPv4
            # Reading 6 bytes for the IP and Port
            target = sock.recv(4)
            targetPort = sock.recv(2)
            target = "." .join([str(ord(i)) for i in target])
        elif atyp == "\x03":  # Hostname
            targetLen = ord(sock.recv(1))  # hostname length (1 byte)
            target = sock.recv(targetLen)
            targetPort = sock.recv(2)
            target = "".join([unichr(ord(i)) for i in target])
        elif atyp == "\x04":  # IPv6
            target = sock.recv(16)
            targetPort = sock.recv(2)
            tmp_addr = []
            for i in xrange(len(target) / 2):
                tmp_addr.append(unichr(ord(target[2 * i]) * 256 + ord(target[2 * i + 1])))
            target = ":".join(tmp_addr)
        targetPort = ord(targetPort[0]) * 256 + ord(targetPort[1])
        if cmd == "\x02":  # BIND
            raise SocksCmdNotImplemented("Socks5 - BIND not implemented")
        elif cmd == "\x03":  # UDP
            raise SocksCmdNotImplemented("Socks5 - UDP not implemented")
        elif cmd == "\x01":  # CONNECT
            if atyp == "\x03":
                try:
                    target = self.gethostbyname(target)
                except:
                    sock.sendall(chr(0) + chr(91) + "\x00"*4 + chr(targetPort / 256) + chr(targetPort % 256))
                    raise RemoteConnectionFailed("[%s:%d] Remote DNS resolving failed" % (target, targetPort))
            serverIp = "".join([chr(int(i)) for i in target.split(".")])
            status = self.setupRemoteSession(target, targetPort)
            if status:
                sock.sendall(VER + SUCCESS + "\x00" + "\x01" + serverIp + chr(targetPort / 256) + chr(targetPort % 256))
                return True
            else:
                sock.sendall(VER + REFUSED + "\x00" + "\x01" + serverIp + chr(targetPort / 256) + chr(targetPort % 256))
                raise RemoteConnectionFailed("[%s:%d] Remote failed" % (target, targetPort))

        raise SocksCmdNotImplemented("Socks5 - Unknown CMD")

    def parseSocks4(self, sock):
        log.debug("SocksVersion4 detected")
        cmd = sock.recv(1)
        if cmd == "\x01":  # Connect
            targetPort = sock.recv(2)
            targetPort = ord(targetPort[0]) * 256 + ord(targetPort[1])
            serverIp = sock.recv(4)
            # skip USERID field
            while sock.recv(1) != "\x00":
                continue
            target = ".".join([str(ord(i)) for i in serverIp])
            # handle SOCKS4A
            if target.startswith("0.0.0.") and not target.endswith(".0"):
                hostname = ""
                b = None
                while b != "\x00":
                    b = sock.recv(1)
                    hostname += b
                hostname = hostname.strip("\x00")
                try:
                    target = self.gethostbyname(hostname)
                except:
                    sock.sendall(chr(0) + chr(91) + serverIp + chr(targetPort / 256) + chr(targetPort % 256))
                    raise RemoteConnectionFailed("[%s:%d] Remote DNS resolving failed" % (target, targetPort))
            serverIp = "".join([chr(int(i)) for i in target.split(".")])
            status = self.setupRemoteSession(target, targetPort)
            if status:
                sock.sendall(chr(0) + chr(90) + serverIp + chr(targetPort / 256) + chr(targetPort % 256))
                return True
            else:
                sock.sendall("\x00" + "\x91" + serverIp + chr(targetPort / 256) + chr(targetPort % 256))
                raise RemoteConnectionFailed("Remote connection failed")
        else:
            raise SocksProtocolNotImplemented("Socks4 - Command [%d] Not implemented" % ord(cmd))

    def handleSocks(self, sock):
        # This is where we setup the socks connection
        ver = sock.recv(1)
        if ver == "\x05":
            return self.parseSocks5(sock)
        elif ver == "\x04":
            return self.parseSocks4(sock)

    def gethostbyname(self, host):
        if host in dns_cache:
            entry = dns_cache[host]
            ttl = DNS_CACHE_TTL - (time() - entry['time'])
            if ttl > 0:
                log.info("Remote DNS Query Result: [%s] <---> [%s] (cached, TTL=%d)" % (host, entry['address'], ttl))
                return entry['address']
        headers = {"X-CMD": "DNS", "X-TARGET": host}
        headers = self.mergeHeaders(headers)
        response = self.conn.urlopen('POST', self.httpPath, headers=headers, body="")
        if response.status == 200 and re.match(r'^\d+(?:\.\d+){3}', response.data):
            dns_cache[host] = entry = { 'address': response.data, 'time': time() }
            log.info("Remote DNS Query Result: [%s] <---> [%s]" % (host, entry['address']))
        else:
            raise Exception("Remote DNS Query Error: [%s]" % (host, ))
        response.close()
        return entry['address']

    def setupRemoteSession(self, target, port):
        headers = {"X-CMD": "CONNECT", "X-TARGET": target, "X-PORT": port}
        headers = self.mergeHeaders(headers)
        self.target = target
        self.port = port
        # response = conn.request("POST", self.httpPath, params, headers)
        response = self.conn.urlopen('POST', self.httpPath, headers=headers, body="")
        if response.status == 200:
            status = response.getheader("x-status")
            if status == "OK":
                self.updateCookies(response.getheaders().getlist("set-cookie"))
                log.info("[%s:%d] HTTP [200]: cookie [%s]" % (self.target, self.port, self.getcookies()))
                return True
            else:
                if response.getheader("X-ERROR") is not None:
                    log.error(response.getheader("X-ERROR"))
        else:
            log.error("[%s:%d] HTTP [%d]: [%s]" % (self.target, self.port, response.status, response.getheader("X-ERROR")))
            log.error("[%s:%d] RemoteError: %s" % (self.target, self.port, response.data))
        return False

    def closeRemoteSession(self):
        headers = {"X-CMD": "DISCONNECT", "Cookie": self.getcookies()}
        headers = self.mergeHeaders(headers)
        params = ""
        response = self.conn.request("POST", self.httpPath, params, headers)
        if response.status == 200:
            log.info("[%s:%d] Connection Terminated" % (self.target, self.port))

    def reader(self):
        while True:
            try:
                if not self.pSocket:
                    break
                headers = {"X-CMD": "READ", "Cookie": self.getcookies(), "Connection": "Keep-Alive"}
                headers = self.mergeHeaders(headers)
                response = self.conn.urlopen('POST', self.httpPath, headers=headers, body="")
                data = None
                if response.status == 200:
                    status = response.getheader("x-status")
                    if status == "OK":
                        if response.getheader("set-cookie") is not None:
                            self.updateCookies(response.getheaders().getlist("set-cookie"))
                        data = response.data
                        # Yes I know this is horrible, but its a quick fix to issues with tomcat 5.x bugs that have been reported, will find a propper fix laters
                        try:
                            if response.getheader("server").find("Apache-Coyote/1.1") > 0:
                                data = data[:len(data) - 1]
                        except:
                            pass
                        if data is None:
                            data = ""
                    else:
                        data = None
                        log.error("[%s:%d] HTTP [%d]: Status: [%s]: Message [%s] Shutting down" % (self.target, self.port, response.status, status, response.getheader("X-ERROR")))
                else:
                    log.error("[%s:%d] HTTP [%d]: Shutting down" % (self.target, self.port, response.status))
                    log.debug("[%s:%d] Message: %s" % (self.target, self.port, response.getheader("X-ERROR")))
                response.close()
                if data is None:
                    # Remote socket closed
                    break
                if len(data) == 0:
                    sleep(0.1)
                    continue
                transferLog.info("[%s:%d] <<<< [%d]" % (self.target, self.port, len(data)))
                self.pSocket.send(data)
            except Exception, ex:
                raise ex
        self.closeRemoteSession()
        log.debug("[%s:%d] Closing localsocket" % (self.target, self.port))
        try:
            self.pSocket.close()
        except:
            log.debug("[%s:%d] Localsocket already closed" % (self.target, self.port))

    def writer(self):
        global READBUFSIZE
        while True:
            try:
                self.pSocket.settimeout(1)
                data = self.pSocket.recv(READBUFSIZE)
                if not data:
                    break
                headers = {"X-CMD": "FORWARD", "Cookie": self.getcookies(), "Content-Type": "application/octet-stream", "Connection": "Keep-Alive"}
                headers = self.mergeHeaders(headers)
                response = self.conn.urlopen('POST', self.httpPath, headers=headers, body=data)
                if response.status == 200:
                    status = response.getheader("x-status")
                    if status == "OK":
                        if response.getheader("set-cookie") is not None:
                            self.updateCookies(response.getheaders().getlist("set-cookie"))
                    else:
                        log.error("[%s:%d] HTTP [%d]: Status: [%s]: Message [%s] Shutting down" % (self.target, self.port, response.status, status, response.getheader("x-error")))
                        break
                else:
                    log.error("[%s:%d] HTTP [%d]: Shutting down" % (self.target, self.port, response.status))
                    log.debug("[%s:%d] Message: %s" % (self.target, self.port, response.getheader("X-ERROR")))
                    break
                transferLog.info("[%s:%d] >>>> [%d]" % (self.target, self.port, len(data)))
            except timeout:
                continue
            except Exception, ex:
                raise ex
                break
        self.closeRemoteSession()
        log.debug("Closing localsocket")
        try:
            self.pSocket.close()
        except:
            log.debug("Localsocket already closed")

    def run(self):
        try:
            if self.handleSocks(self.pSocket):
                log.debug("Staring reader")
                r = Thread(target=self.reader, args=())
                r.start()
                log.debug("Staring writer")
                w = Thread(target=self.writer, args=())
                w.start()
                r.join()
                w.join()
        except SocksCmdNotImplemented, si:
            log.error(si.message)
            self.pSocket.close()
        except SocksProtocolNotImplemented, spi:
            log.error(spi.message)
            self.pSocket.close()
        except Exception, e:
            log.error(e.message)
            try:
                self.closeRemoteSession()
                self.conn.close()
            except:
                pass
            self.pSocket.close()


def askGeorg(connectString, custom_headers={}):
    connectString = connectString
    o = urlparse(connectString)
    try:
        httpPort = o.port
    except:
        if o.scheme == "https":
            httpPort = 443
        else:
            httpPort = 80
    httpScheme = o.scheme
    httpHost = o.netloc.split(":")[0]
    httpPath = o.path
    httpScheme_kwargs = {}
    if o.scheme == "http":
        httpScheme = urllib3.HTTPConnectionPool
    else:
        httpScheme = urllib3.HTTPSConnectionPool
        httpScheme_kwargs['cert_reqs'] = 'CERT_NONE'

    conn = httpScheme(host=httpHost, port=httpPort, **httpScheme_kwargs)
    response = conn.request("GET", httpPath, headers=custom_headers)
    if response.status == 200:
        if BASICCHECKSTRING == response.data.strip():
            log.info(BASICCHECKSTRING)
            return True
    conn.close()
    return False

if __name__ == '__main__':
    print """\033[1m
    \033[1;33m
                     _____
  _____   ______  __|___  |__  ______  _____  _____   ______
 |     | |   ___||   ___|    ||   ___|/     \|     | |   ___|
 |     \ |   ___||   |  |    ||   ___||     ||     \ |   |  |
 |__|\__\|______||______|  __||______|\_____/|__|\__\|______|
                    |_____|
                    ... every office needs a tool like Georg

  willem@sensepost.com / @_w_m__
  sam@sensepost.com / @trowalts
  etienne@sensepost.com / @kamp_staaldraad
  \033[0m
   """
    log.setLevel(logging.DEBUG)
    parser = argparse.ArgumentParser(description='Socks server for reGeorg HTTP(s) tunneller')
    parser.add_argument("-l", "--listen-on", metavar="", help="The default listening address", default="127.0.0.1")
    parser.add_argument("-p", "--listen-port", metavar="", help="The default listening port", type=int, default="8888")
    parser.add_argument("-r", "--read-buff", metavar="", help="Local read buffer, max data to be sent per POST", type=int, default="1024")
    parser.add_argument("-u", "--url", metavar="", required=True, help="The url containing the tunnel script")
    parser.add_argument("-v", "--verbose", metavar="", help="Verbose output[INFO|DEBUG]", default="INFO")
    parser.add_argument("-H", "--custom-header", metavar="", help="Custom HTTP header", nargs='*')
    args = parser.parse_args()
    if (args.verbose in LEVEL):
        log.setLevel(LEVEL[args.verbose])
        log.info("Log Level set to [%s]" % args.verbose)

    log.info("Starting socks server [%s:%d], tunnel at [%s]" % (args.listen_on, args.listen_port, args.url))
    log.info("Checking if Georg is ready")
    if args.custom_header is not None:
        custom_headers = dict(h.split(":", 1) for h in args.custom_header)
    else:
        custom_headers ={}
    if not askGeorg(args.url, custom_headers):
        log.info("Georg is not ready, please check url")
        exit()
    READBUFSIZE = args.read_buff
    servSock = socket(AF_INET, SOCK_STREAM)
    servSock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    servSock.bind((args.listen_on, args.listen_port))
    servSock.listen(1000)
    while True:
        try:
            sock, addr_info = servSock.accept()
            sock.settimeout(SOCKTIMEOUT)
            log.debug("Incomming connection")
            session(sock, args.url, custom_headers).start()
        except KeyboardInterrupt, ex:
            break
        except Exception, e:
            log.error(e)
    servSock.close()
