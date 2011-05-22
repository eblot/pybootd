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

Some options accept a boolean value. The following values are recognized:

- true values: ``on``, ``true``, ``enable``, ``enabled``, ``yes``, ``high``,
  ``ok``, ``1``
- false values: ``off``, ``false``, ``disable``, ``disabled``, ``no``, ``low``,
  ``ko``, ``0``

The BOOTP daemon associates each MAC address to an assigned IP address, so as
long as the BOOTP daemon is running, the same IP address is always assigned to
the same client. The address never gets back to the pool, *i.e.* it cannot be
re-assigned to another machine even if the lease expires.

This is especially useful for a full network installation, where each client
request at least an IP address twice:

- when BIOS kicks off, its PXE ROM code requests for an IP address, then
  requests for an executable to run,
- when the executable runs, it usually boots up an OS (Linux, ...) which in
  turns requests for an IP address to resume the installation.

``[logger]`` section
....................

``type``
   The type of logger, if any. ``stderr``, ``file``, ``syslog`` or ``none``

``level``
   The level of logger verbosity. ``critical``, ``error``, ``info`` or ``debug``

``file``
   The path to the output log file, if ``type`` is set to ``file``

``[bootp]`` section
...................

``access``
   Type of access control list. If this option is not defined, all BOOTP
   requests are served, as long as the defined pool is not exhausted. It can be
   one among:

   - ``mac``: incoming BOOTP requests are filtered out based on the MAC address
     of the requester
   - ``uuid``: incoming PXE requests are filtered out based on the UUID of the
     request. UUID are not emitted from simple BOOTP or DHCP clients, so this
     option is only meaningful for PXE-enabled clients
   - ``http``: incoming requests are forwarded to another host, through simple
     HTTP GET requests. The MAC address, and the UUID if it exists, are sent
     to the HTTP server, which replies to grant or deny the access to the
     BOOTP client.

   A section with the same name should exist to define the access list.

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
   option accepts a boolean value.

``boot_file``
   Boot filename to send back to a BOOTP client, so that it can request it
   over TFTP to boot up after being assigned a network address.

``domain``
   Domain part of the client FQDN, that is the domain name of the network.

``dns``
   IP address of the DNS server.

``lease_time``
   Validity, in seconds, of a DHCP lease. Note that the BOOTP daemon does not
   managed lease expiration, this value has therefore little meaning.

``pool_start``
   First address to allocate for a BOOT client.

``pool_count``
   How many clients can be served

``notify``
   If defined, the IP address and port (using a column separator: a.b.c.d:p)
   to which a UDP notification message should be sent whenever a client
   requests an IP address to the BOOTP daemon.

``port``
   Alternative port for incoming BOOTP requests

``timeout``
   Timeout in seconds to receive a response from a remote authentication host,
   when ACL are enabled using the HTTP protocol. IF no answer is received from
   the remote host, the BOOTP daemon ignores the incoming BOOTP/DHCP request.

``servername``
   Name of the BOOT server, which some clients might expect.

``[mac]`` section
.................

``AA-BB-CC-DD-EE-FF``
   The ``[mac]`` section contains one entry for each MAC address to allow or
   block. The value for each entry is a boolean.

``[uuid]`` section
..................

``xxxxxxxx-aaaa-bbbb-cccc-yyyyyyyyyyyy``
   The ``[uuid]`` section contains one entry for each UUID to allow or block.
   The value for each entry is a boolean.

``[http]`` section
..................

``location``
   The URL prefix to contact the remote server for boot permission.

``pxe``
   The path to append to the URL prefix when the BOOTP client emits PXE
   information. A regular PC with PXE capability emits a PXE boot request when
   the BIOS kicks off. The remote HTTP server may therefore identify a BIOS
   boot when it receives this kind of request from the *pybootd* daemon.

``dhcp``
   The path to append to the URL prefix when the BOOTP client emits simple DHCP
   information. A regular OS emits a simple DHCP request at start up. The
   remote HTTP server may therefore identify an OS boot when it receives this
   kind of request from the *pybootd* daemon.

The dual ``pxe``/``dhcp`` options allow to distinguish the boot phase on the
remote HTTP server: either a BIOS initialization or an OS boot. When such
differentiation is useless, both options may refer to the same path.

``[tftp]`` section
..................

``address``
   Address to listen to incoming TFTP requests. When the BOOTP daemon is
   enabled, this option is better omitted, as the address is automatically
   received from the BOOTP daemon.

``blocksize``
   Size of each data block exchange with the client. It is recommend to
   leave the default value, as some clients may not accept other values

``port``
   Alternative port for incoming TFTP request

``timeout``
   Timeout in seconds to receive an acknowledgment from the TFTP client. If
   the timeout expires, the TFTP server retransmits the last packet. If can
   be expressed as a real value.

``root``
   Base directory for the TFTP service. This path is automatically prepended
   to the pathname issued from the TFTP client. It can either be:

   - a relative path to the daemon directory, if the ``root`` option starts
     with ``./``
   - an absolute path, if the ``root`` option starts with ``/``
   - a URL prefix, to accces remote files

``[filters]`` section
.....................

The ``filters`` option allows on-the-fly pathnames transformation. When a TFTP
request for some specific filenames, the TFTP daemon can translate then to
other ones.

This option can be useful to serve the very same configuration file
(``pxelinux.cfg`` for example) whatever the remote client, hence speeding up
the boot process. This option also enable to access files that are not stored
within the currently configured path (see the ``root`` option).

Each option of the ``filters`` section represents a file pattern to match. It
accepts standard wildcard characters, `*` and `?`. The value defines the
translated path.

The *value* part can contain variables, which are replaced in-place.
Variables are written with enclosing braces, such as ``{varname}``.

For now, the only supported variable is ``filename``, which is replaced with
the actual requested filename.

The *value* part can also contains a special marker, that tells the *tftp*
daemon to read the replacement pattern from a file. This special marker should
be written with enclosing brackets, such as ``[file]``.

Examples
........

The following filter::

  pxelinux.cfg/* = pybootd/etc/pxe.cfg

tells the *tftp* daemon that all client requests that matches the
``pxelinux.cfg/*`` pattern should be server the ``pybootd/etc/pxe.cfg`` file
instead. This avoids the client to perform the usual time-costing fallback
requests using UUID, then MAC, then suffix address before eventually falling
back to the simple ``pxelinux.cfg`` file.

The following filter::

  startup = [dir/{filename}.cfg]

tells the *tftp* daemon that when requested the ``startup`` file, the tftp
daemon should look for the actual name within the ``dir/startup.cfg`` file.

HTTP-based authentication
-------------------------

This option allows to delegate the BOOTP authorization to a remote web server.
Any web server may be used as pybootd emits standard HTTP GET requets and
expects standard HTTP reply codes.

This server receives HTTP GET requests with URLs such as::

  http://server/path?mac=AA-BB-CC-DD-EE-FF&uuid=xxxxxxxx-aaaa-bbbb-cccc-yyyyyyyyyyyy

where ``http://server`` matches the ``location`` option and ``/path`` matches
the ``pxe`` or ``dhcp`` options of the ``[http]`` section.

The web server should reply either with:

- ``200 Ok`` result if the bootp client should be assigned an IP address, or
- ``401 Unauthorized`` result if the bootp client should be ignored.

The ``pybootd`` package contains in the ``tests/`` subdirectory a minimalist
HTTP server that demonstrates this feature. See the ``config.ini`` file for
this test daemon. The test daemon expects the ``pxe`` path to be set to
``/boot`` and the ``dhcp`` path set to ``/linux``.


Sample configurations
~~~~~~~~~~~~~~~~~~~~~

Installing a Debian 6.0 machine from the official archive
---------------------------------------------------------
As the TFTP daemon is able to retrieve remote file, using the HTTP protol,
there is no need to manually download any file from a Debian mirror. The TFTP
daemon will forward all file requests to the mirror on behalf of the client
being installed.

The ``pybootd.ini`` would contain::

  [logger]
  ; show requests on the standard error output of the daemon
  type = stderr
  ; show informative and error messages only (disable verbose mode)
  level = info

  [bootp]
  ; to not force a full PXE boot up cycle to accept the client
  allow_simple_dhcp = enable
  ; First BOOTP/DHCP address to generate
  pool_start = 192.168.1.100
  ; Google DNS
  dns = 8.8.8.8
  ; boot up executable the client should request through TFTP
  boot_file = pxelinux.0

  [tftp]
  ; URL to install a Debian 6.0 Intel/AMD 64-bit network installation
  root = http://http.us.debian.org/debian/dists/squeeze/main/installer-amd64/current/images/netboot

  [filters]
  ; serves a simple configuration file to the linux PXE helper
  pxelinux.cfg/* = pybootd/etc/pxe.cfg

The ``pool_start`` parameter should be a on an existing network on the host,
and the ``root`` URL may be changed to use an alternative mirror and path.

Note that to complete the network installation, the client should be able to
access the remote file on its own - as with a network ISO image. There are two
ways to achieve this:

- either enable IP forwarding on the *pybootd* host (see ``forward.sh``
  script within the ``pybootd`` package), or
- be sure to connect the network cable of the client to a LAN that have
  direct access to the Internet, once the first installation stage is
  complete.
