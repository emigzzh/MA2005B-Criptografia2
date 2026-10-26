dig @172.30.0.101 www.beta.signed A +dnssec
dig @172.30.0.101 beta.signed DNSKEY +dnssec
dig @172.30.0.101 beta.signed DS +dnssec
dig @172.30.0.101 signed DNSKEY +dnssec
dig @172.30.0.101 . DNSKEY +dnssec
dig @172.30.0.101 nonexistente.beta.signed A +dnssec
dig @172.30.0.101 www.gamma.signed A +dnssec
