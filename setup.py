#!/usr/bin/env python3
#
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

#pylint: disable-msg=broad-except
#pylint: disable-msg=no-self-use
#pylint: disable-msg=missing-docstring

from os import close, unlink
from os.path import abspath, dirname, join as joinpath
from py_compile import compile as pycompile, PyCompileError
from re import search as research
from sys import stderr
from tempfile import mkstemp
from setuptools import find_packages, setup
from setuptools.command.build_py import build_py
from pybootd import __version__

def _read(fname):
    return open(joinpath(dirname(__file__), fname)).read()


PACKAGES = find_packages(where='.')
KEYWORDS = 'bootp ftdp dhcp pxe netboot bios uefi'
CLASSIFIERS = [
    'Development Status :: 4 - Beta',
    'Environment :: No Input/Output (Daemon)',
    'Intended Audience :: Developers',
    'Intended Audience :: System Administrators',
    'License :: OSI Approved :: GNU Library or '
        'Lesser General Public License (LGPL)',
    'Operating System :: MacOS :: MacOS X',
    'Operating System :: POSIX :: Linux',
    'Programming Language :: Python :: 3.5',
    'Programming Language :: Python :: 3.6',
    'Programming Language :: Python :: 3.7',
    'Programming Language :: Python :: 3.8',
    'Topic :: Internet',
    'Topic :: System :: Installation/Setup',
    'Topic :: System :: Networking',
    'Topic :: Utilities'
]
INSTALL_REQUIRES = ['netifaces >= 0.10']

HERE = abspath(dirname(__file__))


def read(*parts):
    """
    Build an absolute path from *parts* and and return the contents of the
    resulting file.  Assume UTF-8 encoding.
    """
    with open(joinpath(HERE, *parts), 'rt') as dfp:
        return dfp.read()

META_FILE = read(joinpath('pybootd', '__init__.py'))

def find_meta(meta):
    """
    Extract __*meta*__ from META_FILE.
    """
    meta_match = research(
        r"(?m)^__{meta}__ = ['\"]([^'\"]*)['\"]".format(meta=meta),
        META_FILE
    )
    if meta_match:
        return meta_match.group(1)
    raise RuntimeError("Unable to find __{meta}__ string.".format(meta=meta))


class BuildPy(build_py):
    """Override byte-compile sequence to catch any syntax error issue.

       For some reason, distutils' byte-compile when it forks a sub-process
       to byte-compile a .py file into a .pyc does NOT check the success of
       the compilation. Therefore, any syntax error is explictly ignored,
       and no output file is generated. This ends up generating an incomplete
       package w/ a nevertheless successfull setup.py execution.

       Here, each Python file is build before invoking distutils, so that any
       syntax error is catched, raised and setup.py actually fails should this
       event arise.

       This step is critical to check that an unsupported syntax (for ex. 3.6
       syntax w/ a 3.5 interpreter) does not end into a 'valid' package from
       setuptools perspective...
    """

    def byte_compile(self, files):
        for file in files:
            if not file.endswith('.py'):
                continue
            pfd, pyc = mkstemp('.pyc')
            close(pfd)
            try:
                pycompile(file, pyc, doraise=True)
                self._check_line_width(file)
                continue
            except PyCompileError as exc:
                # avoid chaining exceptions
                print(str(exc), file=stderr)
                raise SyntaxError("Cannot byte-compile '%s'" % file)
            finally:
                unlink(pyc)
        super().byte_compile(files)

    def _check_line_width(self, file):
        with open(file, 'rt') as pfp:
            for lpos, line in enumerate(pfp, start=1):
                if len(line) > 80:
                    print('\n  %d: %s' % (lpos, line.rstrip()))
                    raise RuntimeError("Invalid line width '%s'" % file)


def main():
    setup(
        cmdclass={'build_py': BuildPy},
        name=find_meta('title').lower(),
        description=find_meta('description'),
        license=find_meta('license'),
        url=find_meta('uri'),
        version=find_meta('version'),
        author=find_meta('author'),
        author_email=find_meta('email'),
        maintainer=find_meta('author'),
        maintainer_email=find_meta('email'),
        keywords=KEYWORDS,
        long_description=_read('README.rst'),
        packages=PACKAGES,
        download_url='/'.join((find_meta('uri'), 'tarball/master')),
        install_requires=INSTALL_REQUIRES,
        classifiers=CLASSIFIERS,
        package_data={
            '': ['etc/*.ini', 'etc/*.cfg'],
        },
    )


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(exc, file=stderr)
        exit(1)
