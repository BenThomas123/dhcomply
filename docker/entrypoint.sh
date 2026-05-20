#!/bin/sh
set -eu

DHCP_INTERFACE="${DHCP_INTERFACE:-eth0}"
SERVER_INTERFACE="${SERVER_INTERFACE:-${DHCP_INTERFACE}}"
TCPDUMP_INTERFACE="${TCPDUMP_INTERFACE:-any}"
DHCOMPLY_MODE="${DHCOMPLY_MODE:-N}"
KEA_CONFIG="/etc/kea/kea-dhcp6.conf"
LEASE_FILE="${LEASE_FILE:-/var/lib/dhcp/lease_${DHCP_INTERFACE}.json}"

mkdir -p /etc/kea /var/lib/kea /var/lib/dhcp /run/kea /var/log/kea

sysctl -w net.ipv6.conf.all.disable_ipv6=0 >/dev/null 2>&1 || true
sysctl -w "net.ipv6.conf.${SERVER_INTERFACE}.disable_ipv6=0" >/dev/null 2>&1 || true
sysctl -w "net.ipv6.conf.${SERVER_INTERFACE}.accept_dad=0" >/dev/null 2>&1 || true

ip link set "${SERVER_INTERFACE}" up

if ! ip -6 addr show dev "${SERVER_INTERFACE}" | grep -q "fe80::1/64"; then
    ip -6 addr add fe80::1/64 dev "${SERVER_INTERFACE}" nodad 2>/dev/null || true
fi

if ! ip -6 addr show dev "${SERVER_INTERFACE}" | grep -q "2001:db8:1::1/64"; then
    ip -6 addr add 2001:db8:1::1/64 dev "${SERVER_INTERFACE}" nodad 2>/dev/null || true
fi

ip -6 route replace ff00::/8 dev "${SERVER_INTERFACE}" metric 256 2>/dev/null || true

if ip -6 addr show dev "${SERVER_INTERFACE}" | grep "2001:db8:1::1/64" | grep -q " tentative"; then
    echo "The configured Kea IPv6 address is still tentative on ${SERVER_INTERFACE}." >&2
    ip -6 addr show dev "${SERVER_INTERFACE}" >&2 || true
    exit 1
fi

if ip -6 addr show dev "${SERVER_INTERFACE}" | grep "fe80::1/64" | grep -q " tentative"; then
    echo "The configured link-local IPv6 address is still tentative on ${SERVER_INTERFACE}." >&2
    ip -6 addr show dev "${SERVER_INTERFACE}" >&2 || true
    exit 1
fi

if ! ip -6 route get ff02::1:2 dev "${SERVER_INTERFACE}" >/dev/null 2>&1; then
    echo "IPv6 multicast is not reachable on ${SERVER_INTERFACE}." >&2
    echo "Try running Docker with IPv6 enabled sysctls, or use an IPv6-enabled Docker network." >&2
    ip -6 addr show dev "${SERVER_INTERFACE}" >&2 || true
    ip -6 route show >&2 || true
    exit 1
fi

sed "s/__DHCP_INTERFACE__/${SERVER_INTERFACE}/g" \
    /workspace/docker/kea-dhcp6.conf.template > "${KEA_CONFIG}"

kea-dhcp6 -t "${KEA_CONFIG}"

cat > /etc/dhcomply.conf <<'EOF'
dns-servers
domain-search-list
sol-max-rt
EOF

if [ ! -s /etc/dhcomplyIA.conf ]; then
    cat > /etc/dhcomplyIA.conf <<'EOF'
00000001
00000002
EOF
fi

kea-dhcp6 -c "${KEA_CONFIG}" &
KEA_PID="$!"
TCPDUMP_PID=""
IP_MONITOR_PID=""
KEA_STOP_TIMER_PID=""

cleanup() {
    if [ -n "${KEA_STOP_TIMER_PID}" ]; then
        kill "${KEA_STOP_TIMER_PID}" 2>/dev/null || true
        wait "${KEA_STOP_TIMER_PID}" 2>/dev/null || true
    fi
    if [ -n "${IP_MONITOR_PID}" ]; then
        kill "${IP_MONITOR_PID}" 2>/dev/null || true
        wait "${IP_MONITOR_PID}" 2>/dev/null || true
    fi
    if [ -n "${TCPDUMP_PID}" ]; then
        kill "${TCPDUMP_PID}" 2>/dev/null || true
        wait "${TCPDUMP_PID}" 2>/dev/null || true
    fi
    kill "${KEA_PID}" 2>/dev/null || true
    wait "${KEA_PID}" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

sleep 1

if ! kill -0 "${KEA_PID}" 2>/dev/null; then
    echo "kea-dhcp6 failed to start" >&2
    wait "${KEA_PID}"
    exit 1
fi

(
    sleep 110
    if kill -0 "${KEA_PID}" 2>/dev/null; then
        echo "Stopping kea-dhcp6 after 110 seconds" >&2
        kill "${KEA_PID}" 2>/dev/null || true
    fi
) &
KEA_STOP_TIMER_PID="$!"

echo "Starting tcpdump for DHCPv6 traffic on ${TCPDUMP_INTERFACE}" >&2
tcpdump -i "${TCPDUMP_INTERFACE}" -n -vv -l 'ip6 and udp and (port 546 or port 547)' &
TCPDUMP_PID="$!"

while true; do
    date
    ip a
    if [ -f "${LEASE_FILE}" ]; then
        echo "Current lease file: ${LEASE_FILE}"
        cat "${LEASE_FILE}"
    else
        echo "Lease file not found yet: ${LEASE_FILE}"
    fi
    sleep 30
done &
IP_MONITOR_PID="$!"

sleep 1

/workspace/bin/dhcomply "${DHCOMPLY_MODE}" "${DHCP_INTERFACE}" || \
    echo "dhcomply exited; keeping container alive" >&2

while true; do
    sleep 3600
done
