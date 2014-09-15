# -*- coding: utf-8 -*-
#
# Copyright (c) 2010-2011 Emmanuel Blot <emmanuel.blot@free.fr>
# Copyright (c) 2010-2011 Neotion
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

import os
import re
import select
import socket
import string
import struct
import sys
import time
import thread
import urllib2
import urlparse
from ConfigParser import NoSectionError
from cStringIO import StringIO
from pybootd import pybootd_path
from util import hexline

__all__ = ['TftpServer']

TFTP_PORT = 69


class TftpError(AssertionError):
    """Any TFTP error"""
    pass


class TftpConnection(object):
    RRQ = 1
    WRQ = 2
    DATA = 3
    ACK = 4
    ERR = 5
    OACK = 6
    HDRSIZE = 4  # number of bytes for OPCODE and BLOCK in header

    def __init__(self, server, port=0):
        self.log = server.log
        self.server = server
        self.client_addr = None
        self.sock = None
        self.active = 0 # 0: inactive, 1: active
        self.blockNumber = 0
        self.lastpkt = ''
        self.mode = ''
        self.filename = ''
        self.file = None
        self.time = 0
        self.blocksize = self.server.blocksize
        self.timeout = self.server.timeout
        self._bind('', port)

    def _bind(self, host='', port=TFTP_PORT):
        self.log.debug('bind %s:%d' % (host, port))
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if host or port:
            self.sock.bind((host, port))

    def send(self, pkt=''):
        self.log.debug('send')
        self.sock.sendto(pkt, self.client_addr)
        self.lastpkt = pkt

    def recv(self):
        self.log.debug('recv')
        fno = self.sock.fileno()
        client_addr = self.client_addr
        timeout = self.timeout
        retry = self.server.retry
        while retry:
            r,w,e = select.select([fno], [], [fno], timeout)
            if not r:
                # We timed out -- retransmit
                retry = retry - 1
                self.retransmit()
            else:
                # Read data packet
                pktsize = self.blocksize + self.HDRSIZE
                data, addr = self.sock.recvfrom(pktsize)
                if addr == client_addr:
                    break
        else:
            raise TftpError(4, 'Transfer timed out')
        # end while
        return self.parse(data)

    def _filter_file(self, mo):
        self.log.debug('_filter_file')
        return self.server.filter_file(self, mo)

    def _dynreplace(self, matchobj):
        """Dispatch a dynamic replacement function"""
        self.log.debug('_dynreplace')
        func = getattr(self, '_dynreplace_%s' % matchobj.group(1))
        return func(matchobj)

    def _dynreplace_filename(self, matchobj):
        """Replace the 'filename' keyword with the client related filename"""
        self.log.debug('_dynreplace_filename')
        if not self.server.bootpd:
            return matchobj.string
        client_ip = self.client_addr[0]
        path = self.server.bootpd.get_filename(client_ip)
        return path

    def parse(self, data, unpack=struct.unpack):
        self.log.debug('parse')
        buf = buffer(data)
        pkt = {}
        opcode = pkt['opcode'] = unpack('!h', buf[:2])[0]
        if ( opcode == self.RRQ ) or ( opcode == self.WRQ ):
            resource, mode, options = string.split(data[2:], '\000', 2)
            resource = self.server.fcre.sub(self._filter_file, resource)
            if self.server.root and self.is_url(self.server.root):
                resource = '%s/%s' % (self.server.root, resource)
            else:
                try:
                    resource = pybootd_path(resource)
                except IOError:
                    if not self.server.genfilecre.match(resource):
                        if resource.startswith('^%s' % os.sep):
                            resource = os.path.join( \
                                os.path.dirname(sys.argv[0]),
                                    resource.lstrip('^%s' % os.sep))
                        elif self.server.root:
                            if self.server.root.startswith(os.sep):
                                # Absolute root directory
                                resource = os.path.join(self.server.root,
                                                        resource)
                            else:
                                # Relative root directory, from the daemon path
                                daemonpath = os.path.dirname(sys.argv[0])
                                if not daemonpath.startswith(os.sep):
                                    daemonpath = os.path.normpath( \
                                        os.path.join(os.getcwd(), daemonpath))
                                resource = os.path.join(daemonpath,
                                        self.server.root, resource)
                        resource = os.path.normpath(resource)
            self.log.info("Resource '%s'" % resource)
            pkt['filename'] = resource
            pkt['mode'] = mode
            while options:
                key, value, options = options.split('\000', 2)
                if key == 'blksize':
                    self.blocksize = int(value)
                elif key == 'timeout':
                    self.timeout = float(value)
                pkt[key] = value
        elif opcode == self.ACK:
            block = pkt['block'] = unpack('!h', buf[2:4])[0]
        elif opcode == self.DATA:
            block = pkt['block'] = unpack('!h', buf[2:4])[0]
            data = pkt['data'] = buf[4:]
        elif opcode == self.ERR:
            errnum = pkt['errnum'] = unpack('!h', buf[2:4])[0]
            errtxt = pkt['errtxt'] = buf[4:-1]
        else:
            raise TftpError(4, 'Unknown packet type')
        return pkt

    def retransmit(self):
        if self.lastpkt:
            self.log.debug('Retransmit')
            self.sock.sendto(self.lastpkt, self.client_addr)

    def connect(self, addr, data):
        self.log.debug('connect new connection %s:%d' % addr)
        self.client_addr = addr
        RRQ = self.RRQ
        WRQ = self.WRQ
        DATA = self.DATA
        ACK = self.ACK
        ERR = self.ERR
        self.log.info('Client: %s:%d' % addr)
        try:
            pkt = self.parse(data)
            opcode = pkt['opcode']
            if opcode not in (RRQ, WRQ):
                raise TftpError(4, 'Bad request')

            # Start lock-step transfer
            self.active = 1
            if opcode == RRQ:
                self.handle_rrq(pkt)
            else:
                self.handle_wrq(pkt)

            # Loop until done
            while self.active:
                self.log.debug('Still active: %s:%s' % addr)
                pkt = self.recv()
                opcode = pkt['opcode']
                if opcode == DATA:
                    self.recv_data(pkt)
                elif opcode == ACK:
                    self.recv_ack(pkt)
                elif opcode == ERR:
                    self.recv_err(pkt)
                else:
                    raise TftpError(5, 'Invalid opcode')
            self.log.debug('End of active: %s:%s' % addr)
        except TftpError, detail:
            self.send_error(detail[0], detail[1])
        except:
            import traceback
            self.log.error(traceback.format_exc())
        self.log.debug('Ending connection %s:%s' % addr)

    def recv_ack(self, pkt):
        self.log.debug('recv_ack')
        if pkt['block'] == self.blockNumber:
            # We received the correct ACK
            self.handle_ack(pkt)
        else:
            self.log.warn('Expecting ACK for block %d, received %d' % \
                            (pkt['block'], self.blockNumber))

    def recv_data(self, pkt):
        self.log.debug('recv_data')
        if pkt['block'] == self.blockNumber:
            # We received the correct DATA packet
            self.active = ( self.blocksize == len(pkt['data']) )
            self.handle_data(pkt)

    def recv_err(self, pkt):
        self.log.debug('recv_err')
        self.handle_err(pkt)
        self.retransmit()

    def send_data(self, data, pack=struct.pack):
        self.log.debug('send_data')
        if not self.time:
            self.time = time.time()
        blocksize = self.blocksize
        block = self.blockNumber = self.blockNumber + 1
        lendata = len(data)
        format = '!hh%ds' % lendata
        pkt = pack(format, self.DATA, block, data)
        self.send(pkt)
        self.active = (len(data) == blocksize)
        if not self.active and self.time:
            total = time.time()-self.time
            self.time = 0
            try:
                name = self.file.name
                size = os.stat(name)[6]
                try:
                    self.log.info('File %s send in %.1f s (%.2f MB/s)' % \
                                    (name, total, size/(total*1024*1024)))
                except ZeroDivisionError:
                    self.log.warn('File %s send in no time' % name)
            except AttributeError:
                # StringIO does not have a 'name' attribute
                pass
            except Exception:
                import traceback
                traceback.print_exc()
                pass

    def send_ack(self, pack=struct.pack):
        self.log.debug('send_ack')
        block = self.blockNumber
        self.blockNumber = self.blockNumber + 1
        format = '!hh'
        pkt = pack(format, self.ACK, block)
        self.send(pkt)

    def send_error(self, errnum, errtext, pack=struct.pack):
        self.log.debug('send_error')
        errtext = errtext + '\000'
        format = '!hh%ds' % len(errtext)
        outdata = pack(format, self.ERR, errnum, errtext)
        self.sock.sendto(outdata, self.client_addr)

    def send_oack(self, options, pack=struct.pack):
        self.log.debug('send_oack')
        pkt = pack('!h', self.OACK)
        for k, v in options:
            pkt += k + '\x00' + v + '\x00'
        self.send(pkt)
        # clear out the last packet buffer to prevent from retransmitting it
        self.lastpkt = ''

    def handle_rrq(self, pkt):
        self.log.debug('handle_rrq')
        resource = pkt['filename']
        mode = pkt['mode']
        genfile = self.server.genfilecre.match(resource)
        if 'tsize' in pkt and int(pkt['tsize']) == 0:
            if genfile:
                filesize = len(genfile.group('name'))
            else:
                try:
                    if self.is_url(resource):
                        rp = urllib2.urlopen(resource)
                        meta = rp.info()
                        filesize = int(meta.getheaders('Content-Length')[0])
                    else:
                        filesize = os.stat(resource)[6]
                except Exception:
                    self.active = False
                    self.send_error(1, 'Cannot access resource')
                    self.log.warn('Cannot stat resource %s' % resource)
                    return
            self.log.info('Send size request file %s size: %d' % \
                          (resource, filesize))
            options = [('tsize', str(filesize))]
            if 'blksize' in pkt:
                options.append(('blksize', pkt['blksize']))
            self.send_oack(options)
        if genfile:
            self.log.info('Generating file content: %s', genfile.group('name'))
            self.file = StringIO(resource[1:-1])
        else:
            try:
                if self.is_url(resource):
                    self.log.info("Sending resource '%s'" % resource)
                    self.file = urllib2.urlopen(resource)
                else:
                    resource = os.path.realpath(resource)
                    self.log.info("Sending file '%s'" % resource)
                    self.file = open(resource, 'rb')
            except Exception:
                self.send_error(1, 'Cannot open resource')
                self.log.warn('Cannot open file for reading %s: %s' % \
                              sys.exc_info()[:2])
                return
        if not 'tsize' in pkt:
            self.send_data(self.file.read(self.blocksize))

    def handle_wrq(self, pkt):
        self.log.debug('handle_wrq')
        resource = pkt['filename']
        mode = pkt['mode']
        if self.is_url(resource):
            self.log.error('Writing to URL is not yet supported')
            return
        try:
            self.log.info('Receiving file: %s' % resource)
            self.file = open(resource, 'wb')
        except:
            self.send_error(1, 'Cannot open file')
            self.log.error('Cannot open file for writing %s: %s' % \
                           sys.exc_info()[:2])
            return
        self.send_ack()

    def handle_ack(self, pkt):
        self.log.debug('handle_ack')
        if self.active:
            self.send_data(self.file.read(self.blocksize))

    def handle_data(self, pkt):
        self.log.debug('handle_data')
        self.send_ack()
        data = pkt['data']
        self.file.write(data)

    def handle_err(self, pkt):
        self.log.info('Error packet: %s' % hexline(pkt['errtxt']))

    @staticmethod
    def is_url(path):
        return bool(urlparse.urlsplit(path).scheme)


class TftpServer:
    """TFTP Server
    Implements a threaded TFTP Server.
    Each request is handled in its own thread
    """

    def __init__(self, logger, config, bootpd=None):
        self.log = logger
        self.config = config
        self.sock = []
        self.bootpd = bootpd
        self.blocksize = int(self.config.get('tftp', 'blocksize', '512'))
        self.timeout = float(self.config.get('tftp', 'timeout', '2.0'))
        self.retry = int(self.config.get('tftp', 'blocksize', '5'))
        self.root = self.config.get('tftp', 'root', os.getcwd())
        self.fcre, self.filepatterns = self.get_file_filters()
        self.genfilecre = re.compile(r'\[(?P<name>[\w\.\-]+)\]')

    def bind(self):
        netconfig = self.bootpd and self.bootpd.get_netconfig()
        host = self.config.get('tftp', 'address',
                               netconfig and netconfig['server'])
        if not host:
            raise TftpError('TFTP address no defined')
        port = int(self.config.get('tftp', 'port', str(TFTP_PORT)))
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.append(sock)
        sock.bind((host, port))

    def forever(self):
        while True:
            r,w,e = select.select(self.sock, [], self.sock)
            for sock in r:
                data, addr = sock.recvfrom(516)
                t = TftpConnection(self)
                thread.start_new_thread(t.connect, (addr, data))

    def filter_file(self, connexion, mo):
        # extract the position of the matching pattern, then extract the
        # conversion string from the file convertion sequence
        groupdict = mo.groupdict()
        for group in groupdict:
            filename = groupdict[group]
            if not filename:
                continue
            filepattern = self.filepatterns[group]
            return re.sub(r'\{(\w+)\}', connexion._dynreplace, filepattern)
        raise TftpError('Internal error, file matching pattern issue')

    def get_file_filters(self):
        patterns = []
        replacements = {}
        try:
            for pos, pattern in enumerate(self.config.options('filters'), 1):
                value = self.config.get('filters', pattern).strip()
                pattern = pattern.strip('\r\n \t')
                pattern = pattern.replace('.', '\.')
                pattern = pattern.replace('*', '.*').replace('?', '.')
                pname = 'p%d' % pos
                replacements[pname] = value
                patterns.append('(?P<%s>%s)' % (pname, pattern))
            xre = '^(?:\./)?(?:%s)$' % '|'.join(patterns)
        except NoSectionError:
            xre = '^$'
        return (re.compile(xre), replacements)
