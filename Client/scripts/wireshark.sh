#!/bin/bash

gnome-terminal -- bash -c "echo 'Launching Wireshark with sudo...'; sudo wireshark; echo 'Wireshark closed. Press any key to exit.'; read -n 1; exec bash"