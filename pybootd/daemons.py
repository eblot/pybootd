#!/usr/bin/env python
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

from optparse import OptionParser
from pxed import BootpServer
from pybootd import pybootd_path, PRODUCT_NAME, __version__ as VERSION
from tftpd import TftpServer
from util import logger_factory, EasyConfigParser
import os
import sys
import threading


class BootpDaemon(threading.Thread):
    def __init__(self, logger, config):
        threading.Thread.__init__(self, name="BootpDeamon")
        self.daemon = True
        self._server = BootpServer(logger=logger, config=config)

    def get_netconfig(self):
        return self._server.get_netconfig()

    def get_filename(self, ip):
        return self._server.get_filename(ip)

    def run(self):
        self._server.bind()
        self._server.forever()


class TftpDaemon(threading.Thread):
    def __init__(self, logger, config, bootpd=None):
        threading.Thread.__init__(self, name="TftpDeamon")
        self.daemon = True
        self._server = TftpServer(logger=logger, config=config, bootpd=bootpd)

    def run(self):
        self._server.bind()
        self._server.forever()


def main():
    usage = 'Usage: %prog [options]\n' \
            '   PXE boot up server, a tiny BOOTP/DHCP/TFTP server'
    optparser = OptionParser(usage=usage)
    optparser.add_option('-c', '--config', dest='config',
                         default='pybootd/etc/pybootd.ini',
                         help='configuration file')
    optparser.add_option('-p', '--pxe', dest='pxe', action='store_true',
                         help='enable BOOTP/DHCP/PXE server only')
    optparser.add_option('-t', '--tftp', dest='tftp', action='store_true',
                         help='enable TFTP server only')
    (options, args) = optparser.parse_args(sys.argv[1:])

    if not options.config:
        raise AssertionError('Missing configuration file')

    if options.pxe and options.tftp:
        raise AssertionError('Cannot exclude both servers')

    cfgparser = EasyConfigParser()
    with open(pybootd_path(options.config), 'rt') as config:
        cfgparser.readfp(config)

    logger = logger_factory(logtype=cfgparser.get('logger', 'type', 'stderr'),
                            logfile=cfgparser.get('logger', 'file'),
                            level=cfgparser.get('logger', 'level', 'info'))
    logger.info('-'.join((PRODUCT_NAME, VERSION)))
    try:
        if not options.tftp:
            bt = BootpDaemon(logger, cfgparser)
            bt.start()
        else:
            bt = None
        if not options.pxe:
            ft = TftpDaemon(logger, cfgparser, bt)
            ft.start()
        while True:
            import time
            time.sleep(5)
    except AssertionError, e:
        print >> sys.stderr, "Error: %s" % str(e)
        sys.exit(1)
    except KeyboardInterrupt:
        print "Aborting..."
