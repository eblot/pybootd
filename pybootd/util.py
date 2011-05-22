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

from ConfigParser import SafeConfigParser
import logging
import re
import socket
import struct
import sys

# String values evaluated as a true boolean values
TRUE_BOOLEANS = ['on','true','enable','enabled','yes','high','ok','1']
# String values evaluated as a false boolean values
FALSE_BOOLEANS = ['off','false','disable','disabled','no','low','ko','0']


def to_int(value):
    """Parse a string and convert it into a value"""
    if not value:
        return 0
    if isinstance(value, int):
        return value
    if isinstance(value, long):
        return int(value)
    mo = re.match('(?i)^\s*(\d+)\s*(?:([KM])B?)?\s*$', value)
    if mo:
        mult = { 'k': (1<<10), 'm': (1<<20) }
        value = int(mo.group(1))
        value *= mo.group(2) and mult[mo.group(2).lower()] or 1
        return value
    return int(value.strip(), value.startswith('0x') and 16 or 10)

def to_bool(value, permissive=True):
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    if value.lower() in TRUE_BOOLEANS:
        return True
    if permissive or (value.lower() in FALSE_BOOLEANS):
        return False
    raise AssertionError('"Invalid boolean value: "%s"' % value)

def hexline(data):
    """Convert a binary buffer into a hexadecimal representation"""
    LOGFILTER=''.join([(len(repr(chr(x)))==3) and chr(x) or \
                       '.' for x in range(256)])
    src = ''.join(data)
    hexa = ' '.join(["%02x"%ord(x) for x in src])
    printable = src.translate(LOGFILTER)
    return "(%d) %s : %s" % (len(data), hexa, printable)

def logger_factory(logtype='syslog', logfile=None, level='WARNING',
                   logid='PXEd', format=None):
    # this code has been copied from Trac (MIT modified license)
    logger = logging.getLogger(logid)
    logtype = logtype.lower()
    if logtype == 'file':
        hdlr = logging.FileHandler(logfile)
    elif logtype in ('winlog', 'eventlog', 'nteventlog'):
        # Requires win32 extensions
        hdlr = logging.handlers.NTEventLogHandler(logid,
                                                  logtype='Application')
    elif logtype in ('syslog', 'unix'):
        hdlr = logging.handlers.SysLogHandler('/dev/log')
    elif logtype in ('stderr'):
        hdlr = logging.StreamHandler(sys.stderr)
    else:
        hdlr = logging.handlers.BufferingHandler(0)

    if not format:
        format = 'PXEd[%(module)s] %(levelname)s: %(message)s'
        if logtype in ('file', 'stderr'):
            format = '%(asctime)s ' + format
    datefmt = ''
    if logtype == 'stderr':
        datefmt = '%X'
    level = level.upper()
    if level in ('DEBUG', 'ALL'):
        logger.setLevel(logging.DEBUG)
    elif level == 'INFO':
        logger.setLevel(logging.INFO)
    elif level == 'ERROR':
        logger.setLevel(logging.ERROR)
    elif level == 'CRITICAL':
        logger.setLevel(logging.CRITICAL)
    else:
        logger.setLevel(logging.WARNING)
    formatter = logging.Formatter(format, datefmt)
    hdlr.setFormatter(formatter)
    logger.addHandler(hdlr)

    def logerror(record):
        import traceback
        print record.msg
        print record.args
        traceback.print_exc()
    # uncomment the following line to show logger formatting error
    #hdlr.handleError = logerror

    return logger

def iptoint(ipstr):
    return struct.unpack('!I', socket.inet_aton(ipstr))[0]

def inttoip(ipval):
    return socket.inet_ntoa(struct.pack('!I', ipval))

def get_iface_config(address):
    if not address:
        return None
    try:
        import netifaces
    except ImportError:
        raise AssertionError("netifaces module is not installed")
    pool = iptoint(address)
    for iface in netifaces.interfaces():
        ifinfo = netifaces.ifaddresses(iface)
        if netifaces.AF_INET not in ifinfo:
            continue
        for inetinfo in netifaces.ifaddresses(iface)[netifaces.AF_INET]:
            addr = iptoint(inetinfo['addr'])
            mask = iptoint(inetinfo['netmask'])
            ip = addr & mask
            ip_client = pool & mask
            delta = ip ^ ip_client
            if not delta:
                config = { 'ifname': iface,
                           'server': inttoip(addr),
                           'net': inttoip(ip),
                           'mask': inttoip(mask) }
                return config
    return None

class EasyConfigParser(SafeConfigParser):
    "ConfigParser extension to support default config values"
    def get(self, section, option, default=None):
        if not self.has_section(section):
            return default
        if not self.has_option(section, option):
            return default
        return SafeConfigParser.get(self, section, option)
