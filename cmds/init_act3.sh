#!/bin/bash
# Detiene instancias previas de los autoritativos
sudo pkill -f "named.conf\.(root|unsigned|alpha|signed|beta|gamma|recursive2)"
sleep 1

# IPs de loopback (si ya existen, el error "File exists" es inofensivo
for ip in 10 20 30 40 50 60 100 101; do
	sudo ip addr add 172.30.0.$ip/32 dev lo 2>/dev/null
done

# Autoritativos
sudo named -4 -u bind -c /etc/bind/named.conf.root
sudo named -4 -u bind -c /etc/bind/named.conf.unsigned
sudo named -4 -u bind -c /etc/bind/named.conf.alpha
sudo named -4 -u bind -c /etc/bind/named.conf.recursive2
sudo named -4 -u bind -c /etc/bind/named.conf.signed
sudo named -4 -u bind -c /etc/bind/named.conf.beta
sudo named -4 -u bind -c /etc/bind/named.conf.gamma

# Recursivo
sudo systemctl restart named

echo "Servidores levantados:"
sudo ss -tulpn | grep named | grep ":53"
