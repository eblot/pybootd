#!/bin/sh
# Simple script to enable / disable IP forwarding

case "${OSTYPE}" in
    darwin*)
        WAN_IF="en0"
        LAN_IF=""
        ;;
    linux*)
        WAN_IF="eth0"
        LAN_IF="eth1"
        ;;
    *)
        WAN_IF=""
        LAN_IF=""
        ;;
esac

# Show usage information
usage()
{
    NAME=`basename $0`
    cat <<EOT
$NAME [options] <on|off>
  Enable or disable IP forwarding
    -h            Print this help message
    -i INTERFACE  WAN interface name (default: ${WAN_IF})
    -j INTERFACE  LAN interface name (default: ${LAN_IF})
EOT
}

ENABLE=0

# Parse the command line
while [ $# -ge 0 ]; do
    case "$1" in
      -h)
        usage
        exit 0
        ;;
      -i)
        shift
        WAN_IF=$1
        ;;
      -j)
        shift
        LAN_IF=$1
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

if [ -z "${WAN_IF}" ]; then
    echo "Undefined WAN interface" >&2
    exit 1
fi

if [ -z "${LAN_IF}" ]; then
    echo "Undefined LAN interface" >&2
    exit 1
fi

UID=`id -u`
if [ ${UID} -ne 0 ]; then
    echo "Superuser privileges are required (use sudo)" >&2
    exit 1
fi

case "${OSTYPE}" in
    darwin*)
        if [ ${ENABLE} -eq 1 ]; then
            echo "Enabling IP forwarding through interface ${WAN_IF}"
            sysctl -w net.inet.ip.forwarding=1
            pfctl -F all -f /etc/pf.conf
            conf=`mktemp`
            echo "nat on ${WAN_IF} from ${LAN_IF}:network to any -> (${WAN_IF})" > \
                "${conf}"
            pfctl -e -f "${conf}"
            rm "${conf}"
        else
            echo "Disabling IP forwarding"
            pfctl -F all -f /etc/pf.conf
            sysctl -w net.inet.ip.forwarding=0
        fi
        ;;
    linux*)
        if [ -z "${LAN_IF}" ]; then
            echo "Unknown LAN interface" >&2
            exit 1
        fi
        if [ ${ENABLE} -eq 1 ]; then
            echo "Enabling IP forwarding through interface $WAN_IF"
            iptables -t nat -A POSTROUTING -o ${WAN_IF} -j MASQUERADE
            iptables -A FORWARD -i ${LAN_IF} -j ACCEPT
            echo 1 > /proc/sys/net/ipv4/ip_forward
        else
            echo "Disabling IP forwarding"
            echo 0 > /proc/sys/net/ipv4/ip_forward
        fi
        ;;
    *)
        echo "Forward mode for OS '${OSTYPE}' is not supported yet" >&2
        exit 1
        ;;
esac
