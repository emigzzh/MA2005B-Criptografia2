#!/bin/bash
D=nic.mx          # cambia por tu dominio .mx firmado
S=8.8.8.8

for tipo in SOA NS A AAAA DNSKEY DS; do
    dig @$S $D $tipo +dnssec
done

# Zona padre (.mx): DNSKEY y DS
dig @$S mx DNSKEY +dnssec
dig @$S mx DS +dnssec

# Nombre inexistente para provocar NSEC/NSEC3
dig @$S noexiste12345.$D A +dnssec
dig @$S noexiste12345.mx A +dnssec
