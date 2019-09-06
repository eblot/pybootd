#!/usr/bin/env python3
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

"""Tiny BOOTP/DHCP/TFTP/PXE server"""

from argparse import ArgumentParser
from collections import OrderedDict
from os.path import isfile
from threading import Thread
from sys import exit as sysexit, modules, stderr
from traceback import format_exc

from . import pybootd_path, __version__
from .httpd import HttpServer
from .pxed import BootpServer
from .tftpd import TftpServer
from .util import logger_factory, EasyConfigParser

#pylint: disable-msg=broad-except
#pylint: disable-msg=missing-docstring
#pylint: disable-msg=invalid-name


class Daemon(Thread):

    def __init__(self, debug):
        super(Daemon, self).__init__(name=self.__class__.__name__, daemon=True)
        self._server = None
        self._debug = debug

    def run(self):
        try:
            self._server.start()
        except KeyboardInterrupt:
            raise
        except Exception as exc:
            print('\nError: %s' % exc, stderr)
            if self._debug:
                print(format_exc(chain=False), file=stderr)
            raise

    def stop(self):
        self._server.stop()


class BootpDaemon(Daemon):

    def __init__(self, logger, config, debug):
        super(BootpDaemon, self).__init__(debug)
        self._server = BootpServer(logger=logger, config=config)

    def get_netconfig(self):
        return self._server.get_netconfig()

    def is_managed_ip(self, ip):
        return self._server.is_managed_ip(ip)

    def get_filename(self, ip):
        return self._server.get_filename(ip)


class TftpDaemon(Daemon):

    def __init__(self, logger, config, debug, bootpd=None):
        super(TftpDaemon, self).__init__(debug)
        self._server = TftpServer(logger=logger, config=config, bootpd=bootpd)


class HttpDaemon(Daemon):

    def __init__(self, logger, config, debug, bootpd=None):
        super(HttpDaemon, self).__init__(debug)
        self.daemon = True
        self._server = HttpServer(logger=logger, config=config, bootpd=bootpd)


def main():
    debug = False
    try:
        argparser = ArgumentParser(description=modules[__name__].__doc__)
        argparser.add_argument('-c', '--config',
                               default='pybootd/etc/pybootd.ini',
                               help='configuration file')
        argparser.add_argument('-p', '--pxe', action='store_true',
                               help='only enable BOOTP/DHCP/PXE server')
        argparser.add_argument('-t', '--tftp', action='store_true',
                               help='only enable TFTP server')
        argparser.add_argument('-H', '--http', action='store_true',
                               help='enable HTTP server (default: disabled)')
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
            cfgparser.read_file(config)

        logger = logger_factory(logtype=cfgparser.get('logger', 'type',
                                                      'stderr'),
                                logfile=cfgparser.get('logger', 'file'),
                                level=cfgparser.get('logger', 'level',
                                                    'info'))
        logger.info('-'.join(('pybootd', __version__)))

        daemons = OrderedDict()
        if not args.tftp:
            daemon = BootpDaemon(logger, cfgparser, debug)
            daemon.start()
            daemons['bootp'] = daemon
        if not args.pxe:
            daemon = TftpDaemon(logger, cfgparser, debug,
                                daemons.get('bootp', None))
            daemon.start()
            daemons['tftp'] = daemon
        if args.http:
            daemon = HttpDaemon(logger, cfgparser, debug, daemons.get('bootp'))
            daemon.start()
            daemons['http'] = daemon
        resume = True
        while daemons:
            zombies = set()
            for name, daemon in daemons.items():
                if not resume:
                    daemon.stop()
                daemon.join(0.1)
                if not daemon.is_alive():
                    logger.warn('%s daemon terminated', name)
                    zombies.add(name)
                    resume = False
            for name in zombies:
                del daemons[name]
    except Exception as exc:
        print('\nError: %s' % exc, file=stderr)
        if debug:
            print(format_exc(chain=False), file=stderr)
        sysexit(1)
    except KeyboardInterrupt:
        print("\nAborting...", file=stderr)
        sysexit(2)
