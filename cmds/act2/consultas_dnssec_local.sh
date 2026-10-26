#!/bin/bash
D=nic.mx          # el mismo dominio que usaste con 8.8.8.8

echo "=== RECURSIVO LOCAL (sin @server: systemd-resolved 127.0.0.53) ==="
for tipo in SOA NS A AAAA DNSKEY DS; do
    dig +dnssec $D $tipo
done

# Zona padre (.mx)
dig +dnssec mx DNSKEY
dig +dnssec mx DS

# Nombres inexistentes para provocar NSEC/NSEC3
dig +dnssec noexiste12345.$D A
dig +dnssec noexiste12345.mx A

echo "=== RECURSIVO DEL LABORATORIO (172.30.0.100) ==="
dig @172.30.0.100 +dnssec $D SOA
dig @172.30.0.100 +dnssec $D A
