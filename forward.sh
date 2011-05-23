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

if [ -z "${WAN_IF}" ]; then
    echo "Unknown WAN interface" >&2
    exit 1
fi

if [ ${UID} -ne 0 ];
    echo "Superuser privileges are required" >&2
    exit 1
fi

ENABLE=0

case "${OSTYPE}" in
    darwin*)
        if [ ${ENABLE} -eq 1 ]; then
            echo "Enabling IP forwarding through interface ${WAN_IF}"
            sysctl -w net.inet.ip.forwarding=1
            natd -interface ${WAN_IF}
            ipfw add divert natd ip from any to any via ${WAN_IF}
        else
            echo "Disabling IP forwarding"
            ipfw delete `sudo ipfw show | grep divert | cut -d' ' -f1`
            killall natd
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
