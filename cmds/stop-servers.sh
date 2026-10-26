#!/bin/bash
sudo pkill -f "named.conf\.(root|unsigned|alpha)"
sudo systemctl stop named
echo "Servidores detenidos"
