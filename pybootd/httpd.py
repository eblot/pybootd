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

"""HTTPd tiny server to exercise the pybootd daemon"""

from argparse import ArgumentParser, FileType
from functools import partial
from http.server import SimpleHTTPRequestHandler, HTTPServer
from os import getcwd
from os.path import isfile, join as joinpath, realpath
from sys import exit as sysexit, modules, stderr
from traceback import format_exc
from urllib.parse import parse_qs, urlsplit
from .util import logger_factory, to_bool, to_int, EasyConfigParser


#pylint: disable-msg=broad-except
#pylint: disable-msg=missing-docstring
#pylint: disable-msg=invalid-name


class HttpRequestHandler(SimpleHTTPRequestHandler):

    def __init__(self, *args, **kwargs):
        super(HttpRequestHandler, self).__init__(*args, **kwargs)

    def do_HEAD(self):
        if self._validate():
            super(HttpRequestHandler, self).do_HEAD()

    def do_GET(self):
        if self._validate():
            super(HttpRequestHandler, self).do_GET()

    def log_request(self, code='-', size='-'):
        self.server.log.info('Request: %s %s', code, size)

    def log_error(self, fmt, *args):
        self.server.log.error(fmt, *args)

    def _validate(self):
        log = self.server.log
        bootpd = self.server.bootpd
        if bootpd and self.server.check_ip:
            ipaddr = self.client_address[0]
            if not bootpd.is_managed_ip(ipaddr):
                log.info('Unknown IP: %s', ipaddr)
                self.send_error(401, 'Not authorized')
                return False
        log.debug("Request: %s" % self.path)
        path = realpath(joinpath(self.directory, self.path.lstrip('/')))
        if not path.startswith(self.directory):
            log.info('Malformed path: %s', path)
            self.send_error(403, 'Forbidden')
            return False
        if not isfile(path):
            log.info('Invalid path: %s', path)
            self.send_error(404, 'Not found')
            return False
        return True

class HttpServer(HTTPServer):

    HTTP_SECTION = 'httpd'

    def __init__(self, logger, config, bootpd=None):
        self.log = logger
        self.config = config
        self.bootpd = bootpd
        netconfig = bootpd and bootpd.get_netconfig()
        address = (self.config.get(self.HTTP_SECTION, 'address',
                              netconfig and netconfig['server']),
                   int(self.config.get(self.HTTP_SECTION, 'port', '80')))
        root = realpath(self.config.get(self.HTTP_SECTION, 'root', None))
        self.check_ip = to_bool(self.config.get(self.HTTP_SECTION, 'check_ip',
                                                'yes'))
        self.log.info('Listening to %s:%s' % address)
        handler = partial(HttpRequestHandler, directory=root)
        super(HttpServer, self).__init__(address, handler)

    def start(self):
        self.serve_forever()

    def stop(self):
        self.shutdown()
