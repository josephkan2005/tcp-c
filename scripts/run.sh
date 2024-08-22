#!/bin/sh

set -e

sudo setcap cap_net_admin=eip ./bin/tcp

./bin/tcp $1 &

pid=$! 

sudo ip addr add 192.168.0.1/24 dev tun0 
sudo ip link set up dev tun0

echo "Initialized"
on_kill() {
    kill $pid
    echo "Killed"
}

trap on_kill INT TERM
wait $pid

