#!/bin/bash

iaString="$1"
interface="$2"

cd ../src
make clean
make
clear
sudo ./dhcomply "$iaString" "$interface"
