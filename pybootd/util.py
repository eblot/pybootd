# Copyright (c) 2010-2019 Emmanuel Blot <emmanuel.blot@free.fr>
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

from configparser import ConfigParser, InterpolationSyntaxError
from logging import (DEBUG, INFO, ERROR, CRITICAL, WARNING,
                     Formatter, FileHandler, StreamHandler, getLogger)
from logging.handlers import (BufferingHandler, NTEventLogHandler,
                              SysLogHandler)
from re import match
from socket import inet_aton, inet_ntoa
from subprocess import run
from struct import pack as spack, unpack as sunpack
from sys import platform, stderr, stdout

try:
    import netifaces as nif
except ImportError:
    if platform == 'darwin':
        raise ImportError('netifaces package is not installed')
    nif = None


# String values evaluated as true boolean values
TRUE_BOOLEANS = ['on', 'high', 'true', 'enable', 'enabled', 'yes',  '1']
# String values evaluated as false boolean values
FALSE_BOOLEANS = ['off', 'low', 'false', 'disable', 'disabled', 'no', '0']
# ASCII or '.' filter
ASCIIFILTER = bytearray((''.join([(
    (len(repr(chr(_x))) == 3) or (_x == 0x5c)) and chr(_x) or '.'
    for _x in range(128)]) + '.' * 128).encode('ascii'))


def to_int(value):
    """Parse a value and convert it into an integer value if possible.

       Input value may be:
       - a string with an integer coded as a decimal value
       - a string with an integer coded as a hexadecimal value
       - a integral value
       - a integral value with a unit specifier (kilo or mega)
    """
    if not value:
        return 0
    if isinstance(value, int):
        return int(value)
    mo = match(r'^\s*(\d+)\s*(?:([KMkm]i?)?B?)?\s*$', value)
    if mo:
        mult = {'K': (1000),
                'KI': (1 << 10),
                'M': (1000 * 1000),
                'MI': (1 << 20)}
        value = int(mo.group(1))
        if mo.group(2):
            value *= mult[mo.group(2).upper()]
        return value
    return int(value.strip(), value.startswith('0x') and 16 or 10)


def to_bool(value, permissive=True, allow_int=False):
    """Parse a string and convert it into a boolean value if possible.

       :param value: the value to parse and convert
       :param permissive: default to the False value if parsing fails
       :param allow_int: allow an integral type as the input value

       Input value may be:
       - a string with an integer value, if `allow_int` is enabled
       - a boolean value
       - a string with a common boolean definition
    """
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        if allow_int:
            return bool(value)
        else:
            if permissive:
                return False
            raise ValueError("Invalid boolean value: '%d'", value)
    if value.lower() in TRUE_BOOLEANS:
        return True
    if permissive or (value.lower() in FALSE_BOOLEANS):
        return False
    raise ValueError('"Invalid boolean value: "%s"' % value)


def hexline(data, sep=' '):
    """Convert a binary buffer into a hexadecimal representation

       Return a string with hexadecimal values and ASCII representation
       of the buffer data
    """
    try:
        if isinstance(data, bytes):
            src = bytearray(data)
        elif isinstance(data, bytearray):
            src = data
        elif isinstance(data, str):
            src = data.encode()
        else:
            # data may be a list/tuple
            src = bytearray(b''.join(data))
    except Exception:
        raise TypeError("Unsupported data type '%s'" % type(data))

    hexa = sep.join(["%02x" % x for x in src])
    printable = src.translate(ASCIIFILTER).decode('ascii')
    return "(%d) %s : %s" % (len(data), hexa, printable)


def logger_factory(logtype='syslog', logfile=None, level='WARNING',
                   logid='PXE', format=None):
    # this code has been copied from Trac (MIT modified license)
    logger = getLogger(logid)
    logtype = logtype.lower()
    if logtype == 'file':
        hdlr = FileHandler(logfile)
    elif logtype in ('winlog', 'eventlog', 'nteventlog'):
        # Requires win32 extensions
        hdlr = NTEventLogHandler(logid, logtype='Application')
    elif logtype in ('syslog', 'unix'):
        hdlr = SysLogHandler('/dev/log')
    elif logtype in ('stderr'):
        hdlr = StreamHandler(stderr)
    elif logtype in ('stdout'):
        hdlr = StreamHandler(stdout)
    else:
        hdlr = BufferingHandler(0)

    if not format:
        format = 'PXE[%(module)s] %(levelname)s: %(message)s'
        if logtype in ('file', 'stderr'):
            format = '%(asctime)s ' + format
    datefmt = ''
    if logtype == 'stderr':
        datefmt = '%X'
    level = level.upper()
    if level in ('DEBUG', 'ALL'):
        logger.setLevel(DEBUG)
    elif level == 'INFO':
        logger.setLevel(INFO)
    elif level == 'ERROR':
        logger.setLevel(ERROR)
    elif level == 'CRITICAL':
        logger.setLevel(CRITICAL)
    else:
        logger.setLevel(WARNING)
    formatter = Formatter(format, datefmt)
    hdlr.setFormatter(formatter)
    logger.addHandler(hdlr)
    return logger


def iptoint(ipstr):
    return sunpack('!I', inet_aton(ipstr))[0]


def inttoip(ipval):
    return inet_ntoa(spack('!I', ipval))


def _netifaces_get_iface_config(address):
    pool = iptoint(address)
    for iface in nif.interfaces():
        ifinfo = nif.ifaddresses(iface)
        if nif.AF_INET not in ifinfo:
            continue
        for inetinfo in nif.ifaddresses(iface)[nif.AF_INET]:
            addr_s = inetinfo.get('addr')
            netmask_s = inetinfo.get('netmask')
            if addr_s is None or netmask_s is None:
                continue

            addr = iptoint(addr_s)
            mask = iptoint(netmask_s)
            ip = addr & mask
            ip_client = pool & mask
            delta = ip ^ ip_client
            if not delta:
                config = {'ifname': iface,
                          'server': inttoip(addr),
                          'net': inttoip(ip),
                          'mask': inttoip(mask)}
                return config
    return None


def _iproute_get_iface_config(address):
    pool = iptoint(address)
    iplines = (line.strip()
               for line in run("ip address show").stdout.split('\n'))
    iface = None
    for l in iplines:
        items = l.split()
        if not items:
            continue
        if items[0].endswith(':'):
            iface = items[1][:-1]
        elif items[0] == 'inet':
            saddr, smasklen = items[1].split('/', 1)
            addr = iptoint(saddr)
            masklen = int(smasklen)
            mask = ((1 << masklen) - 1) << (32 - masklen)
            ip = addr & mask
            ip_client = pool & mask
            delta = ip ^ ip_client
            if not delta:
                return {'ifname': iface,
                        'server': inttoip(addr),
                        'net': inttoip(ip),
                        'mask': inttoip(mask)}
    return None


def get_iface_config(address):
    if not address:
        return None
    nifcfg = _netifaces_get_iface_config if nif else _iproute_get_iface_config
    return nifcfg(address)


def is_quoted(str_):
    """Tells whether a string is enclosed in simple- or double- quoted
       markers"""
    str_ = str_.strip()
    return (str_.startswith('"') and str_.endswith('"')) or \
           (str_.startswith("'") and str_.endswith("'"))


class EasyConfigParser(ConfigParser):
    """ConfigParser extension to support default config values and do not
       mess with multi-line option strings"""

    INDENT_SIZE = 8

    InterpolationSyntaxError = InterpolationSyntaxError

    def get(self, section, option, default=None, raw=True, vars=None,
            fallback=None):
        """Return the section:option value if it exists, or the default value
           if either the section or the option is missing"""
        if not self.has_section(section):
            return default
        if not self.has_option(section, option):
            return default
        return ConfigParser.get(self, section, option, raw=raw, vars=vars,
                                fallback=fallback)

    def write(self, filep):
        """Write an .ini-format representation of the configuration state,
           with automatic line wrapping, using improved multi-line
           representation.
        """
        for section in self._sections:
            filep.write("[%s]\n" % section)
            for (key, value) in self._sections[section].items():
                if key != "__name__":
                    filep.write("%s = %s\n" %
                                (key, str(value).replace('\n', '\n' +
                                 ' ' * self.INDENT_SIZE)))
            filep.write("\n")

    def _interpolate(self, section, option, rawval, vars):
        # special overloading of SafeConfigParser._interpolate:
        # do not attempt to interpolate if the string is (double-)quoted
        if is_quoted(rawval):
            return rawval
        # cannot use 'super' here as ConfigParser is outdated
        return ConfigParser._interpolate(self, section, option, rawval, vars)
