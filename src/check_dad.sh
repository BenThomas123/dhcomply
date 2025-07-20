#!/bin/bash

# Usage: ./check_dad.sh <interface>

INTERFACE=$1

if [ -z "$INTERFACE" ]; then
    echo "Usage: $0 <interface>"
    exit 1
fi

# Check if DAD failed is present in the interface details
if ip a show dev "$INTERFACE" | grep -q "dadfailed"; then
    echo "DAD failed on interface $INTERFACE"
    exit 2
else
    exit 0
fi
