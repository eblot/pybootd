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

from distutils.core import setup
from os.path import dirname, join as joinpath
from sys import platform


def _read(fname):
    return open(joinpath(dirname(__file__), fname)).read()


requirements = []
if platform == 'darwin':
    requirements.append('netifaces (>= 0.5)')


setup(
    name='pybootd',
    version='1.6.0',
    description='Simplified BOOTP/DHCP/PXE and TFTP server',
    author='Emmanuel Blot',
    author_email='emmanuel.blot@free.fr',
    license='LGPL v2',
    keywords='bootp ftdp dhcp pxe netboot',
    url='http://github.com/eblot/pybootd',
    download_url='https://github.com/eblot/pybootd/tarball/master',
    packages=['pybootd'],
    requires=requirements,
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: No Input/Output (Daemon)',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: GNU Library or '
            'Lesser General Public License (LGPL)',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: POSIX',
        'Programming Language :: Python :: 3.5',
        'Topic :: Internet',
        'Topic :: System :: Installation/Setup',
        'Topic :: System :: Networking',
        'Topic :: Utilities'
    ],
    package_data={
        '': ['etc/*.ini', 'etc/*.cfg'],
    },
    long_description=_read('README.rst'),
)
