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

"""HTTPd tiny server to exercise the pybootd daemon"""

from argparse import ArgumentParser, FileType
from http.server import BaseHTTPRequestHandler, HTTPServer
from sys import exit as sysexit, modules, stderr
from traceback import format_exc
from urllib.parse import parse_qs, urlsplit
from pybootd.util import logger_factory, to_bool, to_int, EasyConfigParser


#pylint: disable-msg=broad-except
#pylint: disable-msg=missing-docstring
#pylint: disable-msg=invalid-name


class HttpdTestDaemon(HTTPServer):

    class ReqHandler(BaseHTTPRequestHandler):

        def do_GET(self):
            log = self.server.log
            log.debug("GET from %s:%d" % self.client_address)
            log.debug("Request: %s" % self.path)
            urlparts = urlsplit(self.path)
            query = parse_qs(urlparts.query)
            uuid = ''
            if urlparts.path in ('/boot', '/linux'):
                if 'uuid' in query:
                    uuids = query['uuid']
                    for uuid in uuids:
                        uuid = uuid.upper().strip()
                        authorized = self.server.uuids.get(uuid, False)
                        log.info('UUID %s is %s' % (
                            uuid, authorized and 'authorized' or 'rejected'))
                        if authorized:
                            break
                else:
                    authorized = False
                    log.warn('Request does not specify a UUID')
                if authorized:
                    response = '\n\n'  # HTTP protocol, line feed after headers
                    # dummy generation of a tester number
                    tester = sum([to_int('0x%s' % x) for x in uuid.split('-')])
                    clientname = 'Tester-%03d' % (tester & 0xFF)
                    log.info("UUID %s is assigned as %s" % (uuid, clientname))
                    response += 'Client: %s\n' % clientname
                    filename = 'define_filename_here'
                    if urlparts.path == '/linux':
                        response += 'File: %s\n' % filename
                    self.send_response(200, 'Ok')
                    self.wfile.write(response)
                    return
            self.send_error(401, 'Not authorized')
            return

    def __init__(self, logger, parser):
        address = ('localhost', int(parser.get('httpd', 'port', '80')))
        HTTPServer.__init__(self, address, self.ReqHandler)
        self.log = logger
        self.uuids = {}
        access = 'uuid'
        if parser.has_section(access):
            for entry in parser.options(access):
                self.uuids[entry.upper().strip()] = \
                    to_bool(parser.get(access, entry))

    def start(self):
        self.serve_forever()


def main():
    debug = False
    try:
        argparser = ArgumentParser(description=modules[__name__].__doc__)
        argparser.add_argument('-c', '--config', dest='config', required=True,
                               type=FileType('rt'),
                               help='configuration file')
        argparser.add_argument('-d', '--debug', action='store_true',
                               help='enable debug mode')
        args = argparser.parse_args()

        cfgparser = EasyConfigParser()
        cfgparser.read_file(args.config)

        logger = logger_factory(logtype=cfgparser.get('logger', 'type',
                                                      'stderr'),
                                logfile=cfgparser.get('logger', 'file'),
                                level=cfgparser.get('logger', 'level', 'info'))

        bt = HttpdTestDaemon(logger, cfgparser)
        bt.start()
        while True:
            import time
            time.sleep(5)
    except Exception as exc:
        print('\nError: %s' % exc, file=stderr)
        if debug:
            print(format_exc(chain=False), file=stderr)
        sysexit(1)
    except KeyboardInterrupt:
        print("\nAborting...", file=stderr)
        sysexit(2)


if __name__ == '__main__':
    main()
