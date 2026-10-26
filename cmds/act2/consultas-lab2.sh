R=172.30.0.100
ROOT=172.30.0.10
UNS=172.30.0.20

# Limpia la cachè del recursivo para ver el tràfico hacia root y unsigned
sudo systemctl restart named
sleep 2

echo "===== A traves del recursivo"
dig @$R . SOA
dig @$R . NS
dig @$R ns.root A
dig @$R unsigned SOA
dig @$R unsigned NS
dig @$R ns.unsigned A

echo "===== Directo a los autoritativos"
dig @$ROOT . SOA
dig @$ROOT . NS
dig @$ROOT ns.root A
dig @$UNS unsigned SOA
dig @$UNS unsigned NS
dig @$UNS ns.unsigned A
