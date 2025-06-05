#!/bin/bash

$iaString=$1

make clean
make
./dhcomply $1