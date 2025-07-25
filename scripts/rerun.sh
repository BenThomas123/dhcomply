#!/bin/bash

iaString="$1"
interface="$2"

cd ../src
make clean
make
sudo ./dhcomply "$iaString" "$interface"
