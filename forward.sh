#!/bin/sh
# Simple script to enable / disable IP forwarding

# Show usage information
usage()
{
    NAME=`basename $0`
    cat <<EOT
$NAME [options] <on|off>
  Enable or disable IP forwarding
    -h            Print this help message
    -i INTERFACE  WAN interface name
EOT
}

INTERFACE=""
ENABLE=0

# Parse the command line and update configuration
while [ $# -ge 0 ]; do
    case "$1" in
      -h)
        usage
        exit 0
        ;;
      -i)
        shift
        INTERFACE=$1
        ;;
      -*)
        usage
        echo "Unsupported option: $1"
        exit 1
        ;;
      on)
        ENABLE=1
        ;;
      off)
        ENABLE=0
        ;;
      '')
        break
        ;;
      *)
        usage
        echo "Unsupported command: $1"
        exit 1
        ;;
    esac
    shift
done

case "${OSTYPE}" in
    darwin*)
        if [ -z "${INTERFACE}" ]; then
            INTERFACE="en0"
        fi
        if [ ${ENABLE} -eq 1 ]; then
            echo "Enabling IP forwarding through interface $INTERFACE"
            sysctl -w net.inet.ip.forwarding=1
            natd -interface ${INTERFACE}
            ipfw add divert natd ip from any to any via ${INTERFACE}
        else
            echo "Disabling IP forwarding"
            ipfw delete `sudo ipfw show | grep divert | cut -d' ' -f1`
            killall natd
            sysctl -w net.inet.ip.forwarding=0
        fi
        ;;
    linux*)
        echo "Forward mode for Linux is not supported yet" >&2
        exit 1
        ;;
    *)
        echo "Forward mode for OS '${OSTYPE}' is not supported yet" >&2
        exit 1
        ;;
esac
