import subprocess
import sys

pcap = sys.argv[1] if len(sys.argv) > 1 else "traza_dnssec.pcap"

TIPOS = {1: "A", 2: "NS", 6: "SOA", 28: "AAAA", 43: "DS",
         46: "RRSIG", 47: "NSEC", 48: "DNSKEY", 50: "NSEC3"}

cmd = ["tshark", "-r", pcap, "-Y", "dns.flags.response==1", "-T", "fields",
       "-E", "separator=|", "-E", "occurrence=a", "-E", "aggregator=,",
       "-e", "dns.resp.name", "-e", "dns.resp.type", "-e", "dns.resp.ttl"]

res = subprocess.run(cmd, capture_output=True, text=True)
if res.returncode != 0:
    print("ERROR de tshark:", res.stderr)
    sys.exit(1)

vistos = set()
conteo = {}

print(f"{'Nombre':<32}{'Tipo':<8}{'TTL':<8}")
print("-" * 50)

for linea in res.stdout.splitlines():
    f = linea.split("|")
    if len(f) < 3:
        continue
    nombres = f[0].split(",")
    tipos = f[1].split(",")
    ttls = f[2].split(",")
    for n, t, l in zip(nombres, tipos, ttls):
        if not t.isdigit() or int(t) not in TIPOS:
            continue
        tipo = TIPOS[int(t)]
        clave = (n, tipo, l)
        if clave in vistos:
            continue
        vistos.add(clave)
        conteo[tipo] = conteo.get(tipo, 0) + 1
        print(f"{n:<32}{tipo:<8}{l:<8}")

print("\nResumen de tipos encontrados:")
for tipo in ["SOA", "NS", "A", "AAAA", "DNSKEY", "RRSIG", "DS", "NSEC", "NSEC3"]:
    print(f"  {tipo:<7}{conteo.get(tipo, 0)}")
