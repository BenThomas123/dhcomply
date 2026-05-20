#!/bin/bash

# This script isn't super useful on it's own but I keep it incase people want to run wireshark

set -e

INTERFACE="$1"

if [ -z "$INTERFACE" ]; then
    echo "Usage: $0 <interface>"
    exit 1
fi

gnome-terminal -- bash -c "
echo 'Launching Wireshark DHCPv6 capture on interface: $INTERFACE';
sudo wireshark -k -i '$INTERFACE' -f 'udp port 546 or udp port 547';
echo 'Wireshark closed. Press any key to exit.';
read -n 1;
exec bash
"