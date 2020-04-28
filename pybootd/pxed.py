# Copyright (c) 2010-2020 Emmanuel Blot <emmanuel.blot@free.fr>
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

#pylint: disable-msg=broad-except
#pylint: disable-msg=invalid-name
#pylint: disable-msg=missing-docstring
#pylint: disable-msg=too-many-return-statements
#pylint: disable-msg=too-many-branches
#pylint: disable-msg=too-many-locals
#pylint: disable-msg=too-many-statements
#pylint: disable-msg=too-many-nested-blocks
#pylint: disable-msg=too-many-instance-attributes
#pylint: disable-msg=no-name-in-module
#pylint: disable-msg=no-self-use


from binascii import hexlify
from collections import OrderedDict
from os import stat
from os.path import realpath, join as joinpath
from re import compile as recompile, sub as resub
from select import select
from socket import (if_nametoindex, inet_aton, inet_ntoa, socket,
                    AF_INET, SOCK_DGRAM, IPPROTO_UDP, IPPROTO_IP, SOL_SOCKET,
                    SO_BROADCAST, SO_REUSEADDR)
from struct import calcsize as scalc, pack as spack, unpack as sunpack
from sys import platform
from time import sleep
from traceback import format_exc
from typing import Optional, Tuple, Union
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit, urlunsplit
from urllib.request import urlopen
from uuid import UUID
from netifaces import ifaddresses, interfaces
from .tftpd import TftpServer
from .util import hexline, to_bool, iptoint, inttoip, get_iface_config


BOOTP_PORT_REQUEST = 67

BOOTREQUEST = 1
BOOTREPLY = 2

BOOTPFORMAT = '!4bIHH4s4s4s4s16s64s128s64s'
BOOTPFORMATSIZE = scalc(BOOTPFORMAT)
DHCPFORMAT = '!4bIHH4s4s4s4s16s64s128s4s'
DHCPFORMATSIZE = scalc(DHCPFORMAT)

(BOOTP_OP, BOOTP_HTYPE, BOOTP_HLEN, BOOTP_HOPS, BOOTP_XID, BOOTP_SECS,
 BOOTP_FLAGS, BOOTP_CIADDR, BOOTP_YIADDR, BOOTP_SIADDR, BOOTP_GIADDR,
 BOOTP_CHADDR, BOOTP_SNAME, BOOTP_FILE, BOOTP_VEND) = range(15)

BOOTP_FLAGS_NONE = 0
BOOTP_FLAGS_BROADCAST = 1<<15

COOKIE = r'\0x63\0x82\0x53\0x63'

DHCP_OPTIONS = {0: 'Byte padding',
                1: 'Subnet mask',
                2: 'Time offset',
                3: 'Routers',
                4: 'Time servers',
                5: 'Name servers',
                6: 'Domain name servers',
                7: 'Log servers',
                8: 'Cookie servers',
                9: 'Line printer servers',
                10: 'Impress servers',
                11: 'Resource location servers',
                12: 'Host Name',  # + PXE extensions
                13: 'Boot file size',
                14: 'Dump file',
                15: 'Domain name',
                16: 'Swap server',
                17: 'Root path',
                18: 'Extensions path',
                # --- IP layer / host ---
                19: 'IP forwarding',
                20: 'Source routing',
                21: 'Policy filter',
                22: 'Maximum datagram reassembly size',
                23: 'Default IP TTL',
                24: 'Path MTU aging timeout',
                25: 'Path MTU plateau table',
                # --- IP Layer / interface ---
                26: 'Interface MTU',
                27: 'All subnets local',
                28: 'Broadcast address',
                29: 'Perform mask discovery',
                30: 'Mask supplier',
                31: 'Perform router discovery',
                32: 'Router solicitation address',
                33: 'Static route',
                # --- Link layer ---
                34: 'Trailer encapsulation',
                35: 'ARP cache timeout',
                36: 'Ethernet encaspulation',
                # --- TCP ---
                37: 'TCP default TTL',
                38: 'TCP keepalive interval',
                39: 'TCP keepalive garbage',
                # --- Application & Services ---
                40: 'Network Information Service domain',
                41: 'Network Information servers',
                42: 'Network Time Protocol servers',
                43: 'Vendor specific',  # Used by some PXE clients...
                44: 'NetBIOS over TCP/IP name server',
                45: 'NetBIOS over TCP/IP datagram server',
                46: 'NetBIOS over TCP/IP node type',
                47: 'NetBIOS over TCP/IP scope',
                48: 'X Window system font server',
                49: 'X Window system display manager',
                50: 'Requested IP address',
                51: 'IP address lease time',
                52: 'Option overload',
                53: 'DHCP message',
                54: 'Server ID',
                55: 'Param request list',
                56: 'Error message',
                57: 'Message length',
                58: 'Renewal time',
                59: 'Rebinding time',
                60: 'Vendor class identifier',
                61: 'GUID',
                64: 'Network Information Service+ domain',
                65: 'Network Information Service+ servers',
                66: 'TFTP server name',
                67: 'Bootfile name',
                68: 'Mobile IP home agent',
                69: 'Simple Mail Transport Protocol servers',
                70: 'Post Office Protocol servers',
                71: 'Network News Transport Protocol servers',
                72: 'World Wide Web servers',
                73: 'Finger servers',
                74: 'Internet Relay Chat server',
                81: 'Client FQDN',  # https://tools.ietf.org/html/rfc4702
                93: 'System architecture',
                94: 'Network type',
                97: 'UUID',
                119: 'Domain search',
                121: 'Classless static route',
                128: 'DOCSIS full security server',
                # --- PXE vendor-specific (and other crap) ---
                129: 'PXE vendor-specific',
                130: 'PXE vendor-specific',
                131: 'PXE vendor-specific',
                132: 'PXE vendor-specific',
                133: 'PXE vendor-specific',
                134: 'PXE vendor-specific',
                135: 'PXE vendor-specific',
                # ---
                249: 'Private/Classless static route',
                252: 'Private/Proxy autodiscovery',
                255: 'End of DHCP options'}

DHCP_DISCOVER = 1
DHCP_OFFER = 2
DHCP_REQUEST = 3
DHCP_DECLINE = 4
DHCP_ACK = 5
DHCP_NAK = 6
DHCP_RELEASE = 7
DHCP_INFORM = 8
DHCP_RENEWING = 100

DHCP_IP_MASK = 1
DHCP_IP_GATEWAY = 3
DHCP_IP_DNS = 6
DHCP_LEASE_TIME = 51
DHCP_MSG = 53
DHCP_SERVER = 54
DHCP_END = 255

PXE_DISCOVERY_CONTROL = 6
DISCOVERY_MCAST_ADDR = 7
PXE_BOOT_SERVERS = 8
PXE_BOOT_MENU = 9
PXE_MENU_PROMPT = 10


class BootpError(Exception):
    """Bootp error
    """


class BootpServer:
    """BOOTP Server
       Implements bootstrap protocol.
    """

    ACCESS_LOCAL = {'uuid': 128, 'mac': 48}  # Access modes, defined locally
    ACCESS_REMOTE = ['http']  # Access modes, remotely retrieved
    (ST_IDLE, ST_PXE, ST_DHCP) = range(3)  # Current state

    BOOTP_SECTION = 'bootpd'
    BOOT_FILE_SECTION = 'bootfile'
    BUGGY_CLIENT_SECTION = 'buggy_clients'

    def __init__(self, logger, config):
        self.sock = []
        self.log = logger
        self.config = config
        self.uuidpool = {}  # key MAC address value, value UUID value
        self.ippool = {}  # key MAC address string, value assigned IP string
        self.filepool = {}  # key IP string, value pathname
        self.states = {}  # key MAC address string, value client state
        self.pool_start = self.config.get(self.BOOTP_SECTION, 'pool_start')
        if not self.pool_start:
            raise BootpError('Missing pool_start definition')
        self.pool_count = int(self.config.get(self.BOOTP_SECTION,
                                              'pool_count', '10'))

        self.netconfig = get_iface_config(self.pool_start)
        if not self.netconfig:
            host = self.config.get(self.BOOTP_SECTION, 'address', '0.0.0.0')
            self.netconfig = get_iface_config(host)
        if not self.netconfig:
            # the available networks on the host may not match the config...
            raise BootpError('Unable to detect a matching network config')

        keys = sorted(self.netconfig.keys())
        self.log.info('Using %s' % ', '.join(map(
            ':'.join, zip(keys, [self.netconfig[k] for k in keys]))))
        nlist = self.config.get(self.BOOTP_SECTION, 'notify')
        self.notify = []
        if nlist:
            try:
                nlist = nlist.split(';')
                for n in nlist:
                    n = n.strip().split(':')
                    self.notify.append((n[0], int(n[1])))
            except Exception as exc:
                raise BootpError('Invalid notification URL: %s' % exc)
        access = self.config.get(self.BOOTP_SECTION, 'access')
        if not access:
            self.acl = None
        else:
            access = access.lower()
            if access not in list(self.ACCESS_LOCAL) + self.ACCESS_REMOTE:
                raise BootpError('Invalid access mode: %s' % access)
            if not self.config.has_section(access):
                raise BootpError("Missing access section '%s'" % access)
            self.acl = OrderedDict()
            if access in self.ACCESS_LOCAL:
                for entry in self.config.options(access):
                    acl_builder = getattr(self, 'build_%s_acl' % access)
                    kent = acl_builder(entry)
                    self.acl[kent] = to_bool(self.config.get(access, entry))
        self.buggy_clients = OrderedDict()
        if self.config.has_section(self.BUGGY_CLIENT_SECTION):
            for entry in self.config.options(self.BUGGY_CLIENT_SECTION):
                item = self.build_mac_acl(entry)
                self.buggy_clients[item] = \
                    to_bool(self.config.get(self.BUGGY_CLIENT_SECTION, entry))
        self.boot_files = dict()
        if not self.config.options(self.BOOT_FILE_SECTION):
            raise BootpError("Mising '%s' section" % self.BOOT_FILE_SECTION)
        for entry in self.config.options(self.BOOT_FILE_SECTION):
            self.boot_files[entry] = self.config.get(self.BOOT_FILE_SECTION,
                                                     entry)
        if 'default' not in self.boot_files:
            raise BootpError("'%s' section should contain at least the default"
                             "boot file")
        # pre-fill ippool if specified
        if self.config.has_section('static_dhcp'):
            for mac_str, ip_str in config.items('static_dhcp'):
                mac_key = mac_str.upper().replace('-', ':')
                self.ippool[mac_key] = ip_str
                mac = int(resub('[-:]', '', mac_str), 16)
                mask = (1 << self.ACCESS_LOCAL['mac']) - 1
                access_key = (mac, mask)
                if access == 'mac' and access_key not in self.acl:
                    self.acl[access_key] = True
        self.access = access
        self._resume = False

    # Private
    def _notify(self, notice, uuid_str, mac_str, ip):
        if uuid_str:
            msg = ','.join([notice, uuid_str, mac_str, ip])
        else:
            msg = ','.join([notice, mac_str, ip])
        notify_sock = socket(AF_INET, SOCK_DGRAM)
        for n in self.notify:
            self.log.info('Notifying %s with %s' % (n, msg))
            notify_sock.sendto(msg, n)

    # Public

    @staticmethod
    def find_interface(address: str) -> Optional[str]:
        iaddress = sunpack('!I', inet_aton(address))[0]
        for iface in interfaces():
            for confs in ifaddresses(iface).values():
                for conf in confs:
                    if all([x in conf for x in ('addr', 'netmask')]):
                        address = conf['addr']
                        if ':' in address:
                            # IPv6
                            continue
                        netmask = conf['netmask']
                        iaddr = sunpack('!I', inet_aton(address))[0]
                        inet = sunpack('!I', inet_aton(netmask))[0]
                        inic = iaddr & inet
                        ires = iaddress & inet
                        if inic == ires:
                            return iface
        return None

    @staticmethod
    def is_url(path):
        return bool(urlsplit(path).scheme)

    @classmethod
    def build_mac_acl(cls, entry: str) -> Tuple[int, int]:
        parts = entry.split('/', 1)
        values = []
        bitcount = cls.ACCESS_LOCAL['mac']
        maxval = (1 << bitcount) - 1
        for mask, part in enumerate(parts):
            try:
                if mask:
                    value = maxval & ~((1 << int(part)) - 1)
                else:
                    part = resub('[-:]', '', part)
                    value = int(part, 16)
                    value <<= bitcount - len(part)*4
                if not 0 <= value <= maxval:
                    raise ValueError()
                values.append(value)
            except Exception:
                raise ValueError('Invalid ACL value: %s' % entry)
        if len(values) < 2:
            values.append(maxval)
        return tuple(values)

    @classmethod
    def build_uuid_acl(cls, entry: str) -> Tuple[int, int]:
        parts = entry.split('/', 1)
        values = []
        bitcount = cls.ACCESS_LOCAL['uuid']
        maxval = (1 << bitcount) - 1
        for part in parts:
            try:
                value = UUID('{%s}' % part).int
                if not 0 <= value <= maxval:
                    raise ValueError()
                values.append(value)
            except Exception:
                raise ValueError('Invalid ACL value: %s' % entry)
        if len(values) < 2:
            values.append(maxval)
        return tuple(values)

    @classmethod
    def check_acl(cls, acl: dict, access: str, value: Union[bytes, UUID]) \
            -> Union[bool, None]:
        width = cls.ACCESS_LOCAL[access]
        if access == 'mac':
            ival = int(hexlify(value), 16)
        else:
            ival = value.int
        access_key = (ival, (1 << width) - 1)
        if access_key in acl:
            # try direct match
            result = acl[access_key]
        else:
            # find matching filter
            result = None
            for val, mask in acl:
                if ival & mask == val & mask:
                    result = acl[(val, mask)]
                    break
        if result:
            return True
        return result

    def get_netconfig(self):
        return self.netconfig

    def is_managed_ip(self, address):
        return address in self.ippool.values()

    def start(self):
        host = self.config.get(self.BOOTP_SECTION, 'address', '0.0.0.0')
        port = self.config.get(self.BOOTP_SECTION, 'port',
                               str(BOOTP_PORT_REQUEST))
        sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        sock.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
        sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        if self.buggy_clients:
            iface = self.find_interface(self.config.get(self.BOOTP_SECTION,
                                                        'pool_start'))
            if not iface:
                raise BootpError('Unable to retrieve binding interface')
            if platform == 'linux':
                from socket import SO_BINDTODEVICE
                sock.setsockopt(SOL_SOCKET, SO_BINDTODEVICE, iface.encode())
            elif platform == 'darwin':
                IP_BOUND_IF = 25  # unfortunately not mapped to Python
                sock.setsockopt(IPPROTO_IP, IP_BOUND_IF, if_nametoindex(iface))
            else:
                raise BootpError('Bind to interface not supported on %s' %
                                 platform)
        self.sock.append(sock)
        self.log.info('Listening to %s:%s' % (host, port))
        sock.bind((host, int(port)))
        self._resume = True
        while self._resume:
            try:
                r = select(self.sock, [], self.sock, 0.25)[0]
                if not r:
                    continue
                for sock in r:
                    data, addr = sock.recvfrom(556)
                    self.handle(sock, addr, data)
            except Exception as exc:
                self.log.critical('%s\n%s' % (exc, format_exc()))
                sleep(1)

    def stop(self):
        self._resume = False

    def parse_options(self, tail):
        self.log.debug('Parsing DHCP options')
        dhcp_tags = {}
        padding_count = 0
        while tail:
            tag = tail[0]
            # padding
            if tag == 0:
                padding_count += 1
                tail = tail[1:]
                if padding_count > 0xFF:
                    raise ValueError('Padding overflow')
                continue
            padding_count = 0
            if tag == 0xff:
                return dhcp_tags
            length = tail[1]
            (value, ) = sunpack('!%ss' % length, tail[2:2+length])
            tail = tail[2+length:]
            try:
                option = DHCP_OPTIONS[tag]
                self.log.debug(" option %d: '%s', size:%d %s" %
                               (tag, option, length, hexline(value)))
            except KeyError:
                self.log.debug('  unknown option %d (0x%02x), size:%d %s:' %
                               (tag, tag, length, hexline(value)))
                continue
            dhcp_tags[tag] = value

    def build_pxe_options(self, options, server, bootp_buf):
        try:
            client_params = options[55]
        except IndexError:
            client_params = b''
        buf = b''
        try:
            if 97 in client_params:
                uuid = options[97]
                buf += spack('!BB%ds' % len(uuid),
                             97, len(uuid), uuid)
            if 13 in client_params:
                bootfile_size = 0
                path = self.config.get(TftpServer.TFTP_SECTION, 'root', '')
                bootfile_name = bootp_buf[BOOTP_FILE].decode()
                if not self.is_url(path):
                    pathname = realpath(joinpath(path,bootfile_name))
                    try:
                        bootfile_size = stat(pathname).st_size
                    except OSError as exc:
                        self.log.error('Cannot get size of %s: %s',
                                       pathname, exc)
                else:
                    url = joinpath(path, bootp_buf[BOOTP_FILE].decode())
                    try:
                        resource = urlopen(url)
                        bootfile_size = int(resource.info()['Content-Length'])
                    except Exception as exc:
                        self.log.error('Cannot retrieve size of %s: %s',
                                       url, exc)
            if bootfile_size:
                self.log.debug('Bootfile %s is %d byte long',
                               bootfile_name, bootfile_size)
                bootfile_block = (bootfile_size+511)//512
                buf += spack('!BBH', 13, scalc('!H'), bootfile_block)
            if 60 in client_params:
                clientclass = options[60]
                clientclass = clientclass[:clientclass.find(b':')]
                buf += spack('!BB%ds' % len(clientclass),
                             60, len(clientclass), clientclass)
            if 66 in client_params:
                tftp_server = bootp_buf[BOOTP_SNAME]
                buf += spack('!BB%ds' % len(tftp_server), 66,
                             len(tftp_server), tftp_server)
            if 67 in client_params:
                boot_file = bootp_buf[BOOTP_FILE]
                buf += spack('!BB%ds' % len(boot_file), 67,
                             len(boot_file), boot_file)
            # Vendor specific (PXE extension)
            vendor = b''
            vendor += spack('!BBB', PXE_DISCOVERY_CONTROL, 1, 0x0A)
            vendor += spack('!BBHB4s', PXE_BOOT_SERVERS, 2+1+4,
                            0, 1, server)
            srvstr = b'Python'
            vendor += spack('!BBHB%ds' % len(srvstr), PXE_BOOT_MENU,
                            2+1+len(srvstr), 0, len(srvstr), srvstr)
            prompt = b'Stupid PXE'
            vendor += spack('!BBB%ds' % len(prompt), PXE_MENU_PROMPT,
                            1+len(prompt), len(prompt), prompt)
            buf += spack('!BB%ds' % len(vendor), 43,
                         len(vendor), vendor)
            buf += spack('!BBB', 255, 0, 0)
            return buf
        except KeyError as exc:
            self.log.error('Missing options, cancelling: %s' % exc)
            return b''

    def build_dhcp_options(self, clientname):
        if not clientname:
            return b''
        return spack('!BB%ds' % len(clientname),
                     12, len(clientname), clientname)

    def handle(self, sock, addr, data):
        sockname = sock.getsockname()
        self.log.debug('Sender %s:%d on socket %s:%d',
                       addr[0], addr[1], sockname[0], sockname[1])
        if len(data) < DHCPFORMATSIZE:
            self.log.error('Cannot be a DHCP or BOOTP request - too small!')
        tail = data[DHCPFORMATSIZE:]
        buf = list(sunpack(DHCPFORMAT, data[:DHCPFORMATSIZE]))
        if buf[BOOTP_OP] != BOOTREQUEST:
            self.log.warn('Not a BOOTREQUEST')
            return
        options = self.parse_options(tail)
        if options is None:
            self.log.warn('Error in option parsing, ignore request')
            return

        # Extras (DHCP options)
        try:
            dhcp_msg_type = options[53][0]
        except KeyError:
            dhcp_msg_type = None

        server_addr = self.netconfig['server']
        mac_addr = buf[BOOTP_CHADDR][:6]
        identifiers = {'mac': mac_addr}
        mac_str = ':'.join(['%02X' % x for x in mac_addr])
        # is the UUID received (PXE mode)
        if 97 in options and len(options[97]) == 17:
            uuid = UUID(bytes=options[97][1:])
            identifiers['uuid'] = uuid
            pxe = True
            self.log.debug('PXE UUID has been received')
        # or retrieved from the cache (DHCP mode)
        else:
            uuid = self.uuidpool.get(mac_addr, None)
            identifiers['uuid'] = uuid
            pxe = False
            self.log.debug('PXE UUID not present in request')
        uuid_str = str(uuid) if uuid else None
        if uuid_str:
            self.log.info('UUID is %s for MAC %s', uuid_str, mac_str)

        hostname = ''
        filename = ''

        # Basic state machine
        currentstate = self.states.setdefault(mac_str, self.ST_IDLE)
        newstate = currentstate
        if currentstate == self.ST_IDLE:
            if pxe and (dhcp_msg_type == DHCP_DISCOVER):
                # BIOS is booting up, and try to locate a DHCP server
                newstate = self.ST_PXE
        elif currentstate == self.ST_PXE:
            if not pxe and (dhcp_msg_type == DHCP_REQUEST):
                # OS is booting up, and confirm a previous DHCP dicovery
                newstate = self.ST_DHCP
        else:  # currentstate == self.ST_DHCP
            if pxe:
                # OS was running but the BIOS is performing a DHCP request:
                # board has been restarted
                newstate = self.ST_PXE

        # if the state has not evolved from idle, there is nothing to do
        if newstate == self.ST_IDLE:
            sdhcp = 'allow_simple_dhcp'
            simple_dhcp = \
                self.config.has_option(self.BOOTP_SECTION, sdhcp) and \
                to_bool(self.config.get(self.BOOTP_SECTION, sdhcp))
            if not simple_dhcp:
                self.log.info('Request from %s ignored (idle state)' % mac_str)
                return
            if not dhcp_msg_type:
                # Legacy DHCP: assuming discover by default
                dhcp_msg_type = DHCP_DISCOVER

        # if access control is enable
        if self.access:
            # remote access is always validated on each request
            if self.access in self.ACCESS_REMOTE:
                # need to query a host to grant or reject access
                netloc = self.config.get(self.access, 'location')
                path = self.config.get(self.access, pxe and 'pxe' or 'dhcp')
                timeout = int(self.config.get(self.access, 'timeout', '5'))
                always_check = self.config.get(self.access, 'always_check')
                parameters = {'mac': mac_str}
                if uuid:
                    parameters['uuid'] = uuid_str
                if not pxe and mac_str in self.ippool:
                    parameters['ip'] = self.ippool[mac_str]
                item_str = uuid_str or mac_str
                # only bother the authentication host when a state change is
                # required.
                checkhost = currentstate != newstate
                if to_bool(always_check):
                    checkhost = True
                if checkhost:
                    query = urlencode(parameters)
                    urlparts = (self.access, netloc, path, query, '')
                    url = urlunsplit(urlparts)
                    self.log.info('Requesting URL: %s' % url)
                    try:
                        up = urlopen(url, timeout=timeout)
                        for l in up:
                            try:
                                # Look for extra definition within the reply
                                k, v = [x.strip() for x in l.split(':')]
                                k = k.lower()
                                if k == 'client':
                                    hostname = v
                                if k == 'file':
                                    filename = v
                            except ValueError:
                                pass
                    except HTTPError as exc:
                        self.log.error('HTTP Error: %s' % exc)
                        self.states[mac_str] = self.ST_IDLE
                        return
                    except URLError as exc:
                        self.log.critical('Internal error: %s' % exc)
                        self.states[mac_str] = self.ST_IDLE
                        return
            elif mac_str not in self.ippool:
                # local access is only validated if mac addr is not yet known
                item = identifiers.get(self.access, None)
                if not item:
                    self.log.info('Missing %s identifier, '
                                  'ignoring %s request' %
                                  (self.access, mac_str))
                    return
                result = self.check_acl(self.acl, self.access, item)
                if uuid:
                    item_str = '/'.join((uuid_str, mac_str))
                else:
                    item_str = mac_str
                if not result:
                    if result is not None:
                        self.log.info('%s access in ACL is disabled', item_str)
                    else:
                        self.log.info('%s is not in ACL list', item_str)
                    return
            else:
                # mac is registered, that is already authorized
                item_str = mac_str
            self.log.info('%s access is authorized, '
                          'request will be satisfied' % item_str)

        if 55 in options:
            for opt in options[55]:
                try:
                    parameter = DHCP_OPTIONS[opt]
                    self.log.debug('Client request: %s', parameter)
                except KeyError:
                    self.log.warning('Unknown requested option: %d', opt)

        boot_file = self.boot_files['default']
        if 60 in options:
            clientclass = options[60]
            classids = clientclass.split(b':')
            if len(classids) >= 3 and \
                    classids[0].lower() == b'pxeclient' and \
                    classids[1].lower() == b'arch':
                try:
                    architecture = classids[2].decode()
                except UnicodeDecodeError:
                    self.log.error('Unable to decode architecture')
                    return
                try:
                    boot_file = self.boot_files[architecture]
                    self.log.info("Selecting bootfile '%s' for architecture "
                                  "%s", boot_file, architecture)
                except KeyError:
                    self.log.error('No boot file defined for architecture %s',
                                   architecture)
                    return

        # construct reply
        buf[BOOTP_HOPS] = 0
        buf[BOOTP_OP] = BOOTREPLY
        ciaddr = buf[BOOTP_CIADDR]
        if not sunpack('!I', ciaddr)[0]:
            self.log.info('Client needs its address')
            ipaddr = iptoint(self.pool_start)
            ip = None
            if mac_str in self.ippool:
                ip = self.ippool[mac_str]
                self.log.info('Lease for MAC %s already defined as IP %s' %
                              (mac_str, ip))
            else:
                for idx in range(self.pool_count):
                    ipkey = inttoip(ipaddr+idx)
                    self.log.debug('Check for IP %s' % ipkey)
                    if ipkey not in self.ippool.values():
                        self.ippool[mac_str] = ipkey
                        ip = ipkey
                        break
            if not ip:
                raise BootpError('No more IP available in definined pool')

            mask = iptoint(self.config.get(
                self.BOOTP_SECTION, 'netmask', self.netconfig['mask']))
            reply_broadcast = iptoint(ip) & mask
            reply_broadcast |= (~mask) & ((1 << 32)-1)
            buf[BOOTP_YIADDR] = inet_aton(ip)
            buf[BOOTP_SECS] = 0
            buf[BOOTP_FLAGS] = BOOTP_FLAGS_BROADCAST

            relay = buf[BOOTP_GIADDR]
            if sunpack('!I', relay)[0]:
                addr = (inet_ntoa(relay), addr[1])
            else:
                addr = (inttoip(reply_broadcast), addr[1])
            self.log.info('Reply to: %s:%s' % addr)
        else:
            self.log.info('Client IP: %s' % inet_ntoa(ciaddr))
            buf[BOOTP_YIADDR] = ciaddr
            ip = inet_ntoa(buf[BOOTP_YIADDR])
        buf[BOOTP_SIADDR] = inet_aton(server_addr)
        # sname
        buf[BOOTP_SNAME] = \
            '.'.join([self.config.get(self.BOOTP_SECTION,
                                      'servername', 'unknown'),
                      self.config.get(self.BOOTP_SECTION,
                                      'domain', 'localdomain')]).encode()
        # file
        buf[BOOTP_FILE] = boot_file.encode()

        if not dhcp_msg_type:
            self.log.warn('No DHCP message type found, discarding request')
            return
        if dhcp_msg_type == DHCP_DISCOVER:
            self.log.debug('DHCP DISCOVER')
            dhcp_reply = DHCP_OFFER
            self.log.info('Offering lease for MAC %s: IP %s' %
                          (mac_str, ip))
        elif dhcp_msg_type == DHCP_REQUEST:
            self.log.debug('DHCP REQUEST')
            dhcp_reply = DHCP_ACK
            self.log.info('New lease for MAC %s: IP %s' %
                          (mac_str, ip))
        elif dhcp_msg_type == DHCP_RELEASE:
            self.log.info('DHCP RELEASE')
            if not self.notify:
                return
        elif dhcp_msg_type == DHCP_INFORM:
            self.log.info('DHCP INFORM')
            return
        else:
            self.log.error('Unmanaged DHCP message: %d' % dhcp_msg_type)
            return

        # notify the sequencer
        if self.notify:
            if DHCP_REQUEST == dhcp_msg_type:
                if 97 in options:
                    self._notify('BOOT', uuid_str, mac_str, ip)
                else:
                    self._notify('LEASE', uuid_str, mac_str, ip)
            elif DHCP_RELEASE == dhcp_msg_type:
                self._notify('RELEASE', uuid_str, mac_str, ip)
                return

        # Store the filename
        if filename:
            self.log.info("Filename for IP %s is '%s'" % (ip, filename))
            self.filepool[ip] = filename
        else:
            self.log.debug('No filename defined for IP %s' % ip)

        pkt = spack(DHCPFORMAT, *buf)
        pkt += spack('!BBB', DHCP_MSG, 1, dhcp_reply)
        server = inet_aton(server_addr)
        pkt += spack('!BB4s', DHCP_SERVER, 4, server)

        mask = inet_aton(self.config.get(
            self.BOOTP_SECTION, 'netmask', self.netconfig['mask']))

        pkt += spack('!BB4s', DHCP_IP_MASK, 4, mask)

        gateway_addr = self.config.get(self.BOOTP_SECTION, 'gateway', '')
        if gateway_addr:
            gateway = inet_aton(gateway_addr)
        else:
            gateway = server
        pkt += spack('!BB4s', DHCP_IP_GATEWAY, 4, gateway)

        dns = self.config.get(self.BOOTP_SECTION,
                              'dns', None)
        if dns:
            if dns.lower() == 'auto':
                dns_list = self.get_dns_servers() or [inet_ntoa(server)]
            else:
                dns_list = dns.split(';')
            for dns_str in dns_list:
                dns_ip = inet_aton(dns_str)
                pkt += spack('!BB4s', DHCP_IP_DNS, 4, dns_ip)
        pkt += spack('!BBI', DHCP_LEASE_TIME, 4,
                     int(self.config.get(self.BOOTP_SECTION, 'lease_time',
                                         str(24*3600))))

        # do not attempt to produce a PXE-augmented response for
        # regular DHCP requests
        if pxe:
            extra_buf = self.build_pxe_options(options, server, buf)
            if not extra_buf:
                return
        else:
            extra_buf = self.build_dhcp_options(hostname)

        pkt += extra_buf
        pkt += spack('!BB', DHCP_END, 0)

        # update the UUID cache
        if pxe:
            self.uuidpool[mac_addr] = uuid

        if self.check_acl(self.buggy_clients, 'mac', mac_addr):
            self.log.info('Force global broadcast for buggy client %s',
                          mac_str)
            addr = ('255.255.255.255', addr[1])

        # send the response
        sock.sendto(pkt, addr)

        # update the current state
        if currentstate != newstate:
            self.log.info('Moving from state %d to state %d' %
                          (currentstate, newstate))
            self.states[mac_str] = newstate

    def get_dns_servers(self):
        nscre = recompile(r'nameserver\s+(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\s')
        result = []
        try:
            with open('/etc/resolv.conf', 'r') as resolv:
                for line in resolv:
                    mo = nscre.match(line)
                    if mo:
                        dns = mo.group(1)
                        self.log.info('Found nameserver: %s' % dns)
                        result.append(dns)
        except Exception:
            pass
        if not result:
            self.log.info('No nameserver found')
        return result

    def get_filename(self, ip):
        """Returns the filename defined for a host"""
        filename = self.filepool.get(ip, '')
        self.log.info("Filename for IP %s is '%s'" % (ip, filename))
        return filename
