=========
 PyBootd
=========

--------
Overview
--------

PyBootd is a daemon that supports a subset of the BOOTP, DHCP, PXE and TFTP
protocols, with some handy extensions.

One of its main goals is to provide a simple solution to boot up any 
PXE-enabled personal computer, without requiring any other tools but a standard
Python installation.

Pybootd can be used for any network boot up, or to install an OS without any
physical support such as a USB key or CD/DVD.


------------
Requirements
------------

- Python_ 2.6 or above is required. Python_ 3.x is not yet supported.
- Netifaces_ Python module

.. _Python: http://python.org/
.. _Netifaces: http://alastairs-place.net/netifaces/

Permissions:

- DHCP protocol requires the daemon to listen on port 67.
- TFTP protocol requires the daemon to listen on port 69.

 As these ports are within the server range (<1024), the superuser privileges 
 are required on Unix hosts (Linux, Mac OS X, ...) to start up these daemons.

------
Status
------

This project is in beta development stage.

Supported features
------------------
- Access control:

 1. None (any remote host can be served)
 2. MAC address ACL
 3. UUID based ACL - requires PXE protocol
 4. HTTP forwarding - authorization is delegated to a remote server using 
    simple HTTP GET requests

- Local or remote file serving:

 - For example, it is possible to boot up a full Debian system directly from
   the Internet, without storing any file on the pybootd host machine

- Network notification of client requests through UDP messages

- File name translation

  - Files requested from TFTP clients can be filtered and transformed into 
    local filenames using filters

- It is possible to use pybootd with only one of the offered services, either
  TFTP or DHCP
