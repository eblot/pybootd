+++++++
PyBootd
+++++++

Overview
~~~~~~~~

PyBootd is a daemon supporting a subset of the BOOTP, DHCP, PXE, TFTP and HTTP
protocols, with some handy extensions.

One of its main goals is to provide a simple solution to boot up any
PXE-enabled personal computer, with no other tool required but a standard
Python installation.

It is not designed to be feature-complete, but to be used as an easy modifiable
code to develop custom boot solutions

Pybootd can be used for any network boot up, or to install an OS without any
physical support such as a USB key or a CD/DVD.


Requirements
~~~~~~~~~~~~

Python
------

- Python_ 3.5+ or above is required. Python_ 2.x is not longer supported.
- Netifaces_ Python module is required on OS X; on Linux only, iproute2_ can be
  used as an alternative
- Optional: python_pkg_resources_ Python module

.. _Python: http://python.org/
.. _Netifaces: http://alastairs-place.net/netifaces/
.. _iproute2: http://www.linuxfoundation.org/collaborate/workgroups/networking/iproute2
.. _python_pkg_resources: http://pythonhosted.org/distribute/pkg_resources.html

Permissions
-----------

- DHCP protocol requires the daemon to listen on port 67.
- TFTP protocol requires the daemon to listen on port 69.
- HTTP optional daemon may be run on any port.

As these ports are within the server's range (<1024), the superuser privileges
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

- It is possible to use pybootd with only one of the services, either TFTP or
  DHCP

- A very basic HTTP server can be optionally enabled to serve files over HTTP
  for complex hosts that require additional files (such as a root file system)
  after the initial boot sequence.

Warning
~~~~~~~

There is no strong checking of permissions nor robust file path management, so
it is recommended NOT to run this daemon on a host with sensitive content.

Although only read requests are implemented, there is no enforcement or
strong validation of received data and strings from adversary remote clients.


FAQ
~~~

Common errors
-------------

``pybootd.pxed.BootpError: Unable to detect network configuration``
  This error is often triggered when the ``pool_start`` address is not
  part of a valid network. Double check the network configuration and
  fix up the ``[bootpd]`` section so that it matches the actual
  network. If you don't want to allocate addresses dynamically from
  the pool (with ``pool_count = 0``), you still need to specify
  ``pool_start`` to some address in the local network you want to
  serve (*eg.* the address of your local server).

``error: Can't assign requested address``
  This errir is often triggered with an invalid listening address setting.
  Try listening on all IPv4 interfaces with ``address = 0.0.0.0`` and use ACL
  to discard requests from network you do not want to serve.

Configuration
-------------

``pybootd`` has a few option switches. The server offers two services: *bootpd*
(which supports DHCP and PXE extensions) and *tftpd*. It is possible to disable
either services.

Usage: pybootd.py [-h] [-c CONFIG] [-p] [-t] [-d]
   Tiny BOOTP/DHCP/TFTP/PXE server

Options:
  -h, --help            show this help message and exit
  -c CONFIG, --config CONFIG
                        configuration file
  -p, --pxe             only enable BOOTP/DHCP/PXE server
  -t, --tftp            only enable TFTP server
  -H, --http            enable HTTP server (default: disabled)
  -d, --debug           enable debug mode

``pybootd`` daemon uses a configuration file, in ``.ini`` format, for all other
options.

Some options accept a boolean value. The following values are recognized:

- true values: ``on``, ``high``, ``true``, ``enable``, ``enabled``, ``yes``,
               ``1``
- false values: ``off``, ``low``, ``false``, ``disable``, ``disabled``, ``no``,
                ``0``

The BOOTP daemon associates each MAC address to an assigned IP address. As long
as the BOOTP daemon is running, the same IP address is always assigned to the
same client. The address never gets back to the pool, *i.e.* it cannot be
re-assigned to another machine even when the lease expires.

This is especially useful for a full network-based installation, where each
client requests at least an IP address twice:

- when BIOS kicks off, its PXE ROM code requests an IP address, then requests
  an executable to run,
- when the executable runs, it usually boots up an OS (Linux, ...), which in
  turn requests an IP address to resume the installation.

``[logger]`` section
....................

``type``
   The type of logger, if any. ``stderr``, ``file``, ``syslog`` or ``none``.

``level``
   The level of logger verbosity. ``critical``, ``error``, ``info`` or
   ``debug``.

``file``
   The path to the output log file, if ``type`` is set to ``file``.

``[bootpd]`` section
....................

``access``
   Type of access control list. If this option is not defined, all BOOTP
   requests are served, as long as the defined pool is not exhausted. It can be
   one among the following options:

   - ``mac``: incoming BOOTP requests are filtered out based on the MAC address
     of the requester.
   - ``uuid``: incoming PXE requests are filtered out based on the UUID of the
     request. UUIDs are not emitted from simple BOOTP or DHCP clients, so this
     option is only meaningful for PXE-enabled clients.
   - ``http``: incoming requests are forwarded to another host, through simple
     HTTP GET requests. The MAC address and the UUID if it exists, are sent
     to the HTTP server which replies to grant or deny access to the requester.

   A section named after the selected option should exist to define the access
   list.

``address``
   Specifies the network to listen to requesters for receiving incoming BOOTP
   requests. On most hosts, the only valid address is ``0.0.0.0``. Some hosts
   accept subnetworks (such as ``192.168.1.0``). It is recommended not to
   define this option, and use an ACL to reject clients. Hosts will multiple
   network interfaces, it might not be possible to listen to single network.
   Implementing such as feature would require to use RAW sockets, which falls
   out of scope for this simple server.

``allow_simple_dhcp``
   The default behaviour is to expect PXE requests. In order to serve simple
   BOOTP or DHCP requests, this option should be enabled. This option accepts
   a boolean value.

``boot_file``
   Boot filename to send back to the BOOTP client, which usually requests such
   a file over TFTP to boot up after it has been assigned a network address.

``domain``
   Domain part of the client FQDN, that is the network's domain name.

``dns``
   IP addresses of DNS servers. Multiple addresses are separated with
   semicolon. Specify ``auto`` to re-use DNS addresses used by the
   server. Note that most DHCP clients will only consider the first
   DNS address if multiple are provided.

``gateway``
   Specify gateway address in DHCP reply, default to DHCP server address

``lease_time``
   Validity in seconds of a DHCP lease. Please note that the BOOTP daemon does
   not manage lease expiration; this value has therefore little meaning.

``pool_start``
   First address to allocate for a BOOT client. This has to be an
   address in the local network you want to serve, even if
   ``pool_count`` is set to 0, in which case the address of the DHCP
   server is a good choice.

``pool_count``
   The maximum number of IP addresses that can be dynamically
   allocated from the pool to BOOTP/DHCP clients. Set it to 0 to
   prevent server from dynamically allocating IP addresses from the
   pool and see ``static_dhcp`` below.

``notify``
   When defined, the IP address and port (using a column separator:
   ``a.b.c.d:p``) to which a UDP notification message should be sent whenever
   a client requests an IP address to the BOOTP daemon.

``port``
   Alternative port for incoming BOOTP requests.

``timeout``
   Timeout in seconds for a response from a remote authentication host to be
   received, when ACL is enabled and set to use the HTTP protocol. If no answer
   is received from the remote host, the BOOTP daemon ignores the incoming
   BOOTP/DHCP request.

``servername``
   Name of the BOOTP server.


``[mac]`` section
.................

The ``[mac]`` section contains one entry for each MAC address to allow or
block. The value for each entry is a boolean, *i.e.*::

  AA-BB-CC-DD-EE-FF = enable

Note that due to a limitation of the configuration parser, ':' byte separator
in MAC addresses is not allowed, please use '-' separator.


``[static_dhcp]`` section
.........................

The ``[static_dhcp]`` section contains one entry for each MAC
address to associate with a specific IP address. The IP address can be
any IPv4 address in dotted notation, *i.e.*:

  AA-BB-CC-DD-EE-FF = 192.168.1.2

The MAC addresses specified here will automatically be allowed,
unless ``[mac]`` section specifies otherwise.


``[uuid]`` section
..................

The ``[uuid]`` section contains one entry for each UUID to allow or block.
The value for each entry is a boolean, *i.e.*::

  xxxxxxxx-aaaa-bbbb-cccc-yyyyyyyyyyyy = enable


``[http]`` section
..................

``location``
   The URL prefix to contact the remote server for boot permission.

``pxe``
   The path to append to the URL prefix when the requester emits PXE
   information. A regular PC with PXE capability emits a PXE boot request when
   the BIOS kicks off. The remote HTTP server may therefore identify a BIOS
   boot sequence upon receiving this kind of request from the *pybootd* daemon.

``dhcp``
   The path to append to the URL prefix when the requester emits simple DHCP
   information. A regular OS emits a simple DHCP request at start up. The
   remote HTTP server may therefore identify an OS boot sequence upon receiving
   this kind of request from the *pybootd* daemon.

The ``pxe``/``dhcp`` option pair enables the remote HTTP server to identify
the boot phase: either a BIOS initialization or an OS boot sequence. When such
differentiation is useless, both options may refer to the same path.


``[tftpd]`` section
...................

``address``
   Address to listen to incoming TFTP requests. When the BOOTP daemon is
   enabled this option is better omitted, as the address is automatically
   received from the BOOTP daemon.

``blocksize``
   Size of each exchanged data block. It is recommended to leave the default
   value, as some clients may not accept other values.

``port``
   Alternative port for incoming TFTP request.

``timeout``
   Timeout in seconds for an acknowledgment from the TFTP client to be
   received. If the timeout expires the TFTP server retransmits the last
   packet. It can be expressed as a real value.

``root``
   Base directory for the TFTP service. This path is automatically prepended
   to the pathname issued from the TFTP client. It can either be:

   - a relative path to the daemon directory, when the ``root`` option starts
     with ``./``,
   - an absolute path, when the ``root`` option starts with ``/``,
   - a URL prefix, to access remote files.


``[httpd]`` section
...................

``address``
   Address to listen to incoming HTTP requests. When the BOOTP daemon is
   enabled this option is better omitted, as the address is automatically
   received from the BOOTP daemon.

``port``
   Alternative port for incoming HTTP request, default to 80

``root``
   Base directory for the HTTP service. This path is automatically prepended
   to the pathname issued from the TFTP client. It can either point to a local
   directory for now.

``check_ip``
   Whether to enforce HTTP client IP or not. When enabled, requests from
   clients that have not obtained an IP address from the BOOTP daemon are
   rejected.


``[filters]`` section
.....................

The ``filters`` section allows on-the-fly pathnames transformation. When a TFTP
client requests some specific filenames, the *tftpd* server can translate them
to other ones.

This option is useful to serve the very same configuration file (''e.g.''
``pxelinux.cfg``) whatever the remote client, thus speeding up the boot
process. This option also enables to access files that are not stored within
the currently configured path (see the ``root`` option).

Each option of the ``filters`` section represents a file pattern to match. It
accepts standard wildcard characters: `*` and `?`. The option's value defines
the translated path.

The *value* part can contain variables. Variables are written with enclosing
braces, such as ``{varname}``.

For now, the only supported variable is ``filename``, which is replaced with
the actual requested filename.

The *value* part can also contain a special marker, that tells the *tftpd*
server to read the replacement pattern from a file. This special marker should
be written with enclosing brackets, such as ``[file]``.

Examples
........

The following filter::

  pxelinux.cfg/* = pybootd/etc/pxe.cfg

tells the *tftpd* server that all client requests matching the
``pxelinux.cfg/*`` pattern should be served the ``pybootd/etc/pxe.cfg`` file
instead. This prevents the client to perform the usual time-costing fallback
requests using UUID, MAC, and suffix addresses before eventually falling
back to the simple ``pxelinux.cfg`` file.

The following filter::

  startup = [dir/{filename}.cfg]

tells the *tftpd* server that when the ``startup`` file is requested, it should
read out the actual filename from the ``dir/startup.cfg`` file.

HTTP-based authentication
-------------------------

This option enabled the delegation of the BOOTP authorization to a remote web
server. As *pybootd* emits standard HTTP GET requests and expects standard
HTTP reply codes, any web server may be used to manage authorizations.

This web server receives HTTP GET requests with URLs formatted as follows::

  http://server/path?mac=AA-BB-CC-DD-EE-FF&uuid=xxxxxxxx-aaaa-bbbb-cccc-yyyyyyyyyyyy

where:

- ``http://server`` matches the ``location`` option,
- ``/path`` matches the ``pxe`` or ``dhcp`` options of the ``[http]`` section.

The web server should reply either with:

- ``200 Ok`` result if the requester is to be assigned an IP address, or
- ``401 Unauthorized`` result if it is to be ignored.

The ``pybootd`` package contains a minimalist HTTP server that demonstrates
this feature. It can be found within the ``tests/`` subdirectory. See the
``config.ini`` file for this test daemon. The test daemon expects the ``pxe``
path to be set to ``/boot`` and the ``dhcp`` path to ``/linux``.


Sample configurations
~~~~~~~~~~~~~~~~~~~~~

Installing a Debian 6.0 machine from the official archive
---------------------------------------------------------
As pybootd's *tftpd* server is able to retrieve remote files using the HTTP
protocol, there is no need to manually download any file from a Debian mirror.
The daemon will forward all file requests to the mirror on behalf of the client
being installed.

The ``pybootd.ini`` would contain::

  [logger]
  ; show requests on the standard error output of the daemon
  type = stderr
  ; show informative and error messages only (disable verbose mode)
  level = info

  [bootpd]
  ; do not force a full PXE boot-up cycle to accept the client
  allow_simple_dhcp = enable
  ; First BOOTP/DHCP address to generate
  pool_start = 192.168.1.100
  ; Google DNS
  dns = 8.8.8.8
  ; boot-up executable the client should request through TFTP
  boot_file = pxelinux.0

  [tftpd]
  ; URL to install a Debian 6.0 Intel/AMD 64-bit network installation
  root = http://http.us.debian.org/debian/dists/squeeze/main/installer-amd64/current/images/netboot

  [filters]
  ; serve a simple configuration file to the linux PXE helper
  pxelinux.cfg/* = pybootd/etc/pxe.cfg

The ``pool_start`` parameter should be a valid address on the host's networks,
and the ``root`` URL may be changed to use alternative mirror and path.

Please note that to complete the network installation, the client should be
able to access the remote resources on its own - as with a network ISO image
installation. There are two ways to achieve this:

- either enable IP forwarding on the *pybootd* host (see ``forward.sh``
  script within the ``pybootd`` package), or
- be sure to connect the network cable of the client to a LAN that has direct
  access to the Internet, once the first installation stage is complete.
