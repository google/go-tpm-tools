#!/bin/bash
# This script listens on UDP port 2080, executes received commands in bash,
# and returns the output (stdout and stderr) to the sender.

echo "Starting UDP listener on port 2080..."

# UDP4-LISTEN:2080 -> Listens on UDP port 2080
# fork -> Creates a child process for each request so the main listener stays alive
# EXEC:"/bin/bash" -> Runs the received data as a command in bash
# stderr -> Redirects standard error to the network socket so you see errors too

socat UDP4-LISTEN:2080,fork EXEC:"/bin/bash -c 'bash 2>&1 | tee /dev/ttyS0'"
