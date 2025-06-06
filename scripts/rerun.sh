#!/bin/bash

$iaString=$1
$interface=$2

cd ../src
make clean
make
./dhcomply $1 $2
