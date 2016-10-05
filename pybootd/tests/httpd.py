#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2010-2016 Emmanuel Blot <emmanuel.blot@free.fr>
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

import sys
import urlparse
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from optparse import OptionParser
from util import logger_factory, to_bool, to_int, EasyConfigParser


class HttpdDaemon(HTTPServer):

    class ReqHandler(BaseHTTPRequestHandler):

        def do_GET(self):
            log = self.server.log
            log.debug("GET from %s:%d" % self.client_address)
            log.debug("Request: %s" % self.path)
            urlparts = urlparse.urlsplit(self.path)
            query = urlparse.parse_qs(urlparts.query)
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


if __name__ == "__main__":
    usage = 'Usage: %prog [options]\n' \
            '   HTTPd tiny server to exercise the pybootd daemon'
    optparser = OptionParser(usage=usage)
    optparser.add_option('-c', '--config', dest='config',
                         help='configuration file')
    (options, args) = optparser.parse_args(sys.argv[1:])

    if not options.config:
        raise AssertionError('Missing configuration file')

    cfgparser = EasyConfigParser()
    with open(options.config, 'rt') as config:
        cfgparser.readfp(config)

    logger = logger_factory(logtype=cfgparser.get('logger', 'type', 'stderr'),
                            logfile=cfgparser.get('logger', 'file'),
                            level=cfgparser.get('logger', 'level', 'info'))

    try:
        bt = HttpdDaemon(logger, cfgparser)
        bt.start()
        while True:
            import time
            time.sleep(5)
    except KeyboardInterrupt:
        print "Aborting..."
