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

import os
import sys

def _get_package_name(default='', version='1.5.0'):
    from pkg_resources import WorkingSet
    ws = WorkingSet()
    _path, _ = os.path.split(os.path.dirname( \
                                    sys.modules['pybootd'].__file__))
    _path = os.path.normpath(_path)
    if 'nt' not in os.name:
        for dist in ws:
            if os.path.samefile(os.path.normpath(dist.location), _path):
                return dist.project_name, dist.version
    else: #tweak for windows
        _path = os.path.abspath(_path).lower()
        for dist in ws:
            if 'pybootd' in dist.location:
                if _path == os.path.abspath(dist.location).lower():
                    return dist.project_name, dist.version
    return default, version
PRODUCT_NAME, __version__ = _get_package_name('pybootd')

def pybootd_path(path):
    newpath = ''
    if path.startswith(os.sep):
        newpath = path
    elif os.path.exists(path):
        newpath = path
    else:
        try:
            from pkg_resources import Requirement, resource_filename
            newpath = resource_filename(Requirement.parse(PRODUCT_NAME), path)
            if not newpath:
                from pkg_resources import get_distribution
                localpath = get_distribution(PRODUCT_NAME).location
                newpath = os.path.join(localpath, path)
        except KeyError:
            raise IOError('No such file or directory (resource)')
    if not os.path.isfile(newpath) and not os.path.isdir(newpath):
        raise IOError('No such file or directory (local)')
    return newpath

