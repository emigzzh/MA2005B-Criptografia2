dig @172.30.0.100 www.beta.signed A +dnssec
dig @172.30.0.100 beta.signed DNSKEY +dnssec
dig @172.30.0.100 beta.signed DS +dnssec
dig @172.30.0.100 nonexistente.beta.signed A +dnssec
dig @172.30.0.100 www.gamma.signed A +dnssec
