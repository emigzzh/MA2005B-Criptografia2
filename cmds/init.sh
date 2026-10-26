# Detiene instancias previas de los autoritativos
echo -e "\n Deteniendo instancias previas de los autoritativos"
sudo pkill -f "named.conf\.(root|unsigned|alpha|delta|eta|iota|test|badalg|expired|nods|walkable|signed|beta|gamma|zeta|theta|kappa|recursive2)"
sleep 5

sudo rm -f /tmp/named-*.pid /var/cache/bind/named-*.pid

echo -e "\n Levantando IPs de loopback"
declare -A IPS=(
  [root]=10
  [unsigned]=20 [alpha]=21 [delta]=22 [eta]=23 [iota]=24
  [test]=30 [badalg]=31 [expired]=32 [nods]=33 [walkable]=34
  [signed]=40 [beta]=41 [gamma]=42 [zeta]=43 [theta]=44 [kappa]=45
  [recursive1]=100 [recursive2]=101
)

for nombre in "${!IPS[@]}"; do
  sudo ip addr add 172.30.0.${IPS[$nombre]}/32 dev lo 2>/dev/null
done

# Autoritativos
echo -e "\n Levantando instancias de servidor DNS"
sudo named -4 -u bind -c /etc/bind/named.conf.root
sudo named -4 -u bind -c /etc/bind/named.conf.unsigned
sudo named -4 -u bind -c /etc/bind/named.conf.alpha
sudo named -4 -u bind -c /etc/bind/named.conf.recursive2
sudo named -4 -u bind -c /etc/bind/named.conf.signed
sudo named -4 -u bind -c /etc/bind/named.conf.beta
sudo named -4 -u bind -c /etc/bind/named.conf.gamma
sudo named -4 -u bind -c /etc/bind/named.conf.test
sudo named -4 -u bind -c /etc/bind/named.conf.delta
sudo named -4 -u bind -c /etc/bind/named.conf.eta
sudo named -4 -u bind -c /etc/bind/named.conf.iota
sudo named -4 -u bind -c /etc/bind/named.conf.zeta
sudo named -4 -u bind -c /etc/bind/named.conf.theta
sudo named -4 -u bind -c /etc/bind/named.conf.kappa
sudo named -4 -u bind -c /etc/bind/named.conf.badalg
sudo named -4 -u bind -c /etc/bind/named.conf.expired
sudo named -4 -u bind -c /etc/bind/named.conf.nods
sudo named -4 -u bind -c /etc/bind/named.conf.walkable

# Recursivo
sudo systemctl restart named

sleep 10

echo ""
echo "Esperando a que todas las instancias terminen de levantar..."
IPS="10 20 21 22 23 24 30 31 32 33 34 40 41 42 43 44 45 100 101"
for intento in $(seq 1 15); do
  faltan=0
  for ip in $IPS; do
    sudo ss -tlpn | grep -q "172.30.0.$ip:53" || faltan=1
  done
  if [ $faltan -eq 0 ]; then
    echo "Todo listo (intento $intento)"
    break
  fi
  sleep 1
done

echo -e "\n Servidores levantados:"
echo -e "\nIP esperada    | TCP | UDP"
for ip in 10 20 21 22 23 24 30 31 32 33 34 40 41 42 43 44 45 100 101; do
  tcp=$(sudo ss -tlpn | grep -q "172.30.0.$ip:53" && echo "OK" || echo "--")
  udp=$(sudo ss -ulpn | grep -q "172.30.0.$ip:53" && echo "OK" || echo "--")
  printf "172.30.0.%-6s | %-3s | %-3s\n" "$ip" "$tcp" "$udp"
done
