sudo setcap cap_net_admin=eip ../bin/tcp

../bin/tcp $1

sudo ip addr add 192.168.0.1/24 dev tun0
sudo ip link set up dev tun0
