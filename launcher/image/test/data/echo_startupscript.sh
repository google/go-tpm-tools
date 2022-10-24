#!/bin/bash
echo "Executing startup script"
sudo chmod 666 /dev/ttyS0
sudo echo "Executing startup script: logging to serial" > /dev/ttyS0
