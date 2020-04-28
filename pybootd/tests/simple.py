#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2020, Emmanuel Blot <emmanuel.blot@free.fr>
# All rights reserved.
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

#pylint: disable-msg=empty-docstring
#pylint: disable-msg=missing-docstring
#pylint: disable-msg=invalid-name
#pylint: disable-msg=global-statement

from binascii import hexlify, unhexlify
from io import StringIO
from socket import (if_nametoindex, socket, timeout, AF_INET, SOCK_DGRAM,
                    IPPROTO_IP, IPPROTO_UDP, SOL_SOCKET, SO_BROADCAST,
                    SO_REUSEADDR)
from sys import modules
from textwrap import fill
from time import sleep
from unittest import TestCase, TestSuite, makeSuite, main as ut_main
from pybootd.daemons import BootpDaemon
from pybootd.util import EasyConfigParser, logger_factory


class PxeSimpleTestCase(TestCase):
    """Simple PXE test case.
    """

    @classmethod
    def setUpClass(cls):
        cls.logger = logger_factory(logtype='stdout',
                                    level='DEBUG')
        cfgparser = EasyConfigParser()
        config = StringIO("""
[logger]
type = stdout
level = debug

[bootpd]
address = 0.0.0.0
port = 67
pool_start = 127.0.0.100
pool_count = 5
servername = localhost
domain = localdomain
server_name = debug
lease_time = 86400
access = mac
allow_simple_dhcp = enable

[bootfile]
; BIOS boot file
default = pxelinux.0

[mac]
00-0A-86-A2-2F-3E = enable
            """)
        cfgparser.read_file(config)
        cls.config = cfgparser
        cls.server_port = int(cls.config.get('bootpd', 'port', '67'))

    def setUp(self):
        self.server = BootpDaemon(logger=self.logger, config=self.config,
                                  debug=True)
        self.sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        self.sock.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
        self.sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        self.sock.settimeout(1)
        self.sock.bind(('', self.server_port+1))
        self.server.start()
        # be sure the server can be scheduled and started before resuming
        sleep(0.1)

    def tearDown(self):
        if self.sock:
            self.sock.close() 
        self.server.stop()

    def test(self):
        """Doc.
        """
        discover = """
        010106002233445a0000800000000000000000000000000000000000000a86a22f3e
        00000000000000000000000000000000000000000000000000000000000000000000
        00000000000000000000000000000000000000000000000000000000000000000000
        00000000000000000000000000000000000000000000000000000000000000000000
        00000000000000000000000000000000000000000000000000000000000000000000
        00000000000000000000000000000000000000000000000000000000000000000000
        00000000000000000000000000000000000000000000000000000000000000006382
        5363ff00000000000000000000000000000000000000000000000000000000000000
        00000000000000000000000000000000000000000000000000000000
        """

        request = """
        010106002233445a0000800000000000000000000000000000000000000a86a22f3e
        00000000000000000000000000000000000000000000000000000000000000000000
        00000000000000000000000000000000000000000000000000000000000000000000
        0000000000003c24496e7465724e6963686520506f727461626c65205443502f4950
        2c2076302e3042657461000000000000000000000000000000000000000000000000
        00000000000000000000000000000000000000000000000000000000000000000000
        00000000000000000000000000000000000000000000000000000000000000ff6382
        53633501033204c0a801190104ffffff000304c0a8013a3304000151803704010306
        0f3604c0a8013a5106696e69636865000000000000000000340101ff000000000000
        00000000000000000000000000000000000000000000000000000000000000000000
        00000000000000000000000000000000000000000000000000000000000000000000
        00000000000000000000000000000000000000000000000000000000000000000000
        00000000000000000000000000000000000000000000000000000000000000000000
        00000000000000000000000000000000000000000000000000000000000000000000
        00000000000000000000000000000000000000000000000000000000000000000000
        00000000000000000000000000000000000000000000000000000000000000000000
        00000000
        """
        for step, hexdata in enumerate((discover, request), start=1):
            req = unhexlify(hexdata.replace(' ', '').replace('\n', ''))
            address = '<broadcast>'
            self.sock.sendto(req, (address, self.server_port))
            try:
                fail = False
                resp = self.sock.recv(1024)
                self.logger.debug('response:\n%s',
                      fill(hexlify(resp).decode(),
                           initial_indent='  ',
                           subsequent_indent='  '))
            except timeout:
                fail = True
            if fail:
                self.assertFalse(True,
                                 'No response from server @ step %s' % step)

def suite():
    suite_ = TestSuite()
    suite_.addTest(makeSuite(PxeSimpleTestCase, 'test'))
    return suite_


def main():
    import doctest
    doctest.testmod(modules[__name__])
    try:
        ut_main(defaultTest='suite')
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
