#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
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

"""Boot up server, a tiny BOOTP/DHCP/TFTP/PXE server"""


from os.path import isfile
from threading import Thread
from sys import exit as sysexit, modules, stderr
from . import pybootd_path, PRODUCT_NAME, __version__ as VERSION
from .pxed import BootpServer
from .tftpd import TftpServer
from .util import logger_factory, EasyConfigParser


class BootpDaemon(Thread):

    def __init__(self, logger, config):
        super(BootpDaemon, self).__init__(name="BootpDeamon")
        self.daemon = True
        self._server = BootpServer(logger=logger, config=config)

    def get_netconfig(self):
        return self._server.get_netconfig()

    def get_filename(self, ip):
        return self._server.get_filename(ip)

    def run(self):
        self._server.bind()
        self._server.forever()


class TftpDaemon(Thread):

    def __init__(self, logger, config, bootpd=None):
        super(TftpDaemon, self).__init__(name="TftpDeamon")
        self.daemon = True
        self._server = TftpServer(logger=logger, config=config, bootpd=bootpd)

    def run(self):
        self._server.bind()
        self._server.forever()


def main():
    debug = False
    try:
        from argparse import ArgumentParser
        argparser = ArgumentParser(description=modules[__name__].__doc__)
        argparser.add_argument('-c', '--config', dest='config',
                               default='pybootd/etc/pybootd.ini',
                               help='configuration file')
        argparser.add_argument('-p', '--pxe', dest='pxe',
                               action='store_true',
                               help='enable BOOTP/DHCP/PXE server only')
        argparser.add_argument('-t', '--tftp', dest='tftp',
                               action='store_true',
                               help='enable TFTP server only')
        argparser.add_argument('-d', '--debug', action='store_true',
                               help='enable debug mode')
        args = argparser.parse_args()
        debug = args.debug

        if not isfile(args.config):
            argparser.error('Invalid configuration file')

        if args.pxe and args.tftp:
            argparser.error('Cannot exclude PXE & TFTP servers altogether')

        cfgparser = EasyConfigParser()
        with open(pybootd_path(args.config), 'rt') as config:
            cfgparser.readfp(config)

        logger = logger_factory(logtype=cfgparser.get('logger', 'type',
                                                      'stderr'),
                                logfile=cfgparser.get('logger', 'file'),
                                level=cfgparser.get('logger', 'level',
                                                    'info'))
        logger.info('-'.join((PRODUCT_NAME, VERSION)))

        daemon = None
        if not args.tftp:
            daemon = BootpDaemon(logger, cfgparser)
            daemon.start()
        if not args.pxe:
            daemon = TftpDaemon(logger, cfgparser, daemon)
            daemon.start()
        if daemon:
            while True:
                daemon.join(0.5)
                if not daemon.is_alive():
                    break
    except Exception as e:
        print('\nError: %s' % e, file=stderr)
        if debug:
            import traceback
            print(traceback.format_exc(), file=stderr)
        sysexit(1)
    except KeyboardInterrupt:
        print("Aborting...")
