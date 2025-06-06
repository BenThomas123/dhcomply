#!/bin/bash

$iaString=$1
$interface=$2

make clean
make
./dhcomply $1 $2