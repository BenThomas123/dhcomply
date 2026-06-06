#!/bin/bash

set -e

iaString="$1"
interface="$2"

cd ../
make clean
make
cd bin
sudo rm /var/lib/dhcp/*
sudo ./dhcomply "$iaString" "$interface"
