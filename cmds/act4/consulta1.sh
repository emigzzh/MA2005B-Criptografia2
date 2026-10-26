sudo rndc flush

# DS publicados correctamente en signed
echo "--- DS PUBLICADO ---"
dig @172.30.0.40 zeta.signed DS +dnssec | grep -E "status|flags"
dig @172.30.0.40 theta.signed DS +dnssec | grep -E "status|flags"

# Validación end-to-end con recursive2 (debe mostrar ad)
echo "--- RECUrSIVE2 ---"
dig @172.30.0.101 www.zeta.signed A +dnssec | grep -E "status|flags"
dig @172.30.0.101 www.theta.signed A +dnssec | grep -E "status|flags"
dig @172.30.0.101 zeta.signed DNSKEY +dnssec | grep -E "status|flags"
dig @172.30.0.101 theta.signed DNSKEY +dnssec | grep -E "status|flags"

# Confirmar que beta sigue intacta después de 3 re-firmados de signed
dig @172.30.0.101 www.beta.signed A +dnssec | grep -E "status|flags"

# Confirmar que gamma y kappa siguen sin validar (esperado, sin firmar)
echo "--- NO FIRMADOS EN SIGNED ---"
dig @172.30.0.101 www.gamma.signed A +dnssec | grep -E "status|flags"
dig @172.30.0.101 www.kappa.signed A +dnssec | grep -E "status|flags"

# recursive1 (sin validación) debe resolver todo, sin ad en ningún caso
echo "--- RECURSIVE1 ---"
dig @172.30.0.100 www.zeta.signed A +dnssec | grep -E "status|flags"
dig @172.30.0.100 www.theta.signed A +dnssec | grep -E "status|flags"
