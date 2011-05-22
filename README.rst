+++++++
PyBootd
+++++++

Overview
~~~~~~~~

PyBootd is a daemon that supports a subset of the BOOTP, DHCP, PXE and TFTP
protocols, with some handy extensions.

One of its main goals is to provide a simple solution to boot up any
PXE-enabled personal computer, without requiring any other tools but a standard
Python installation.

Pybootd can be used for any network boot up, or to install an OS without any
physical support such as a USB key or CD/DVD.

Requirements
~~~~~~~~~~~~

Python
------

- Python_ 2.6 or above is required. Python_ 3.x is not yet supported.
- Netifaces_ Python module

.. _Python: http://python.org/
.. _Netifaces: http://alastairs-place.net/netifaces/

Permissions
-----------

- DHCP protocol requires the daemon to listen on port 67.
- TFTP protocol requires the daemon to listen on port 69.

 As these ports are within the server range (<1024), the superuser privileges
 are required on Unix hosts (Linux, Mac OS X, ...) to start up these daemons.

Status
~~~~~~

This project is in beta development stage.

Supported features
~~~~~~~~~~~~~~~~~~
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

FAQ
~~~

Common errors
-------------

``pybootd.pxed.BootpError: Unable to detect network configuration``
  This error is often triggered when the ``pool_start`` address is not part of
  a valid network. Double check the network configuration and fix up the
  ``[bootp]`` section so that it match the actual network.

Configuration
-------------

``pybootd`` as a few option switches. The daemon offers two services: Bootp
(which supports Dhcp and PXE extensions) and Tftp. It is possible to disable
either services.

Usage: pybootd.py [options]
   PXE boot up server, a tiny BOOTP/DHCP/TFTP server

Options:
  -h, --help            show this help message and exit
  -c CONFIG, --config=CONFIG
                        configuration file
  -p, --pxe             enable BOOTP/DHCP/PXE server only
  -t, --tftp            enable TFTP server only

``pybootd`` daemon uses a configuration file, in .ini format, for all other
options.

Logger section
..............

``type``
   The type of logger, if any. ``stderr``, ``file``, ``syslog`` or ``none``

``level``
   The level of logger verbosity. ``critical``, ``error``, ``info`` or ``debug``

``file``
   The path to the output log file, if ``type`` is set to ``file``

``[bootp]`` section
...................

``access``
   Type of access control list. Either ``mac``, ``uuid``, ``http``. If this
   option is not defined, all BOOTP requests are served, as long as the defined
   pool is not exhausted. A section with the same name should exist to define
   the access list.

``address``
   Which network to listen to on the host for receiving incoming BOOTP
   requests. On most hosts, the only valid address is ``0.0.0.0``. Some hosts
   accepts subnetworks (such as ``192.168.1.0``). It is recommended not to
   define this option, and use an ACL to reject clients. On hosts that have
   more than one network cards, it might not be possible to listen on a
   single network interface. It would require a much more complex
   implementation, using RAW sockets.

``allow_simple_dhcp``
   The default behaviour of the daemon is to expect PXE requests. In order to
   serve simple BOOTP or DHCP requests, this option should be enabled. This
   option is a boolean value, ``on``, ``enable``, ``yes``, ``true``, or ``1``
   are considered as a *true* value.

``boot_file``
   The boot filename to send back to a BOOTP client, so that it can request it
   over TFTP to boot up after being assigned a network address.

``domain``
   The domain part of the client FQDN, that is the domain name of the network.

``dns``
   IP address of the DNS server.

``lease_time``
   Validity, in seconds, of a DHCP lease. Note that the BOOTP daemon does not
   managed lease expiration, this value has therefore little meaning.

``pool_start``
   First address to allocate for a BOOT client. The BOOTP daemon associates the
   MAC address to an assigned IP address, so as long as the BOOTP daemon is
   running, the same IP address is always assigned to the same client. The
   address never gets back to the pool, *i.e.* it cannot be re-assigned to
   another machine even if the lease expires.

``pool_count``
   How many clients can be served

``notify``
   If defined, the IP address and port (using a column separator: a.b.c.d:p)
   to which a UDP notification message should be sent whenever a client
   requests an IP address to the BOOTP daemon.

``port``
   Alternative port for incoming BOOTP requests

``timeout``

``servername``
   Name of the BOOT server, which some clients might expect.

``[mac]`` section
.................

``mac`` requires ``mac`` section which enumerates
the allowed clients based on their MAC address. ``

``[uuid]`` section
..................

``[http]`` section
..................
location
   =
pxe
   =
dhcp
   =

``[tftp]`` section
..................

``address``
   = <received from bootp>
``blocksize``
   = 512
``filters``
   =
``port``
   = 69
``timeout``
   = 2.0
``root``
   = <current working directory>
   = http://http.us.debian.org/debian/dists/squeeze/main/installer-amd64/current/images/netboot


Sample configurations
~~~~~~~~~~~~~~~~~~~~~

Installing a Debian 6.0 machine from the official archive
---------------------------------------------------------
As the TFTP daemon is able to retrieve remote file, using the HTTP protol,
there is no need to manually download any file from a Debian mirror. The TFTP
daemon will forward the file requests to the mirror on behalf of the host being
installed.

The ``pybootd.ini`` would contain::

  [logger]
  type = stderr
  level = info

  [bootp]
  allow_simple_dhcp = enable
  pool_start = 192.168.10.100
  dns = 8.8.8.8
  boot_file = pxelinux.0
  lease_time = 86400
  boot_file = pxelinux.0

  [tftp]
  root = http://http.us.debian.org/debian/dists/squeeze/main/installer-amd64/current/images/netboot

The ``pool_start`` parameter should be a valid IP address on the machine, and
the ``root`` URL may be changed to use an alternative mirror and path.
