import subprocess
import sys

pcap = sys.argv[1] if len(sys.argv) > 1 else "traza_lab.pcap"

# Una fila por registro de respuesta. Se pide una sección a la vez para
# no mezclar campos de distintos registros.
campos = [
    "frame.number", "ip.src", "ip.dst",
    "dns.resp.name", "dns.resp.type", "dns.resp.ttl",
    "dns.a", "dns.ns",
    "dns.soa.mname", "dns.soa.rname", "dns.soa.serial_number",
    "dns.soa.refresh_interval", "dns.soa.retry_interval",
    "dns.soa.expire_limit", "dns.soa.mininum_ttl",
]

cmd = ["tshark", "-r", pcap, "-Y", "dns.flags.response==1", "-T", "fields",
       "-E", "separator=|", "-E", "occurrence=a", "-E", "aggregator=,"]
for c in campos:
    cmd += ["-e", c]

res = subprocess.run(cmd, capture_output=True, text=True)
if res.returncode != 0:
    print("ERROR de tshark", res.stderr)
    sys.exit(1)
salida = res.stdout

tipos = {"1": "A", "2": "NS", "6": "SOA"}
vistos = set()

print(f"{'Origen':<14}{'Nombre':<20}{'Tipo':<5}{'TTL':<8}Datos")
print("-" * 90)

for linea in salida.splitlines():
    f = linea.split("|")
    if len(f) < len(campos):
        continue
    (num, src, dst, nombres, tipos_rr, ttls, a, ns,
     mname, rname, serial, refresh, retry, expire, minimo) = f[:15]

    n = nombres.split(",")
    t = tipos_rr.split(",")
    l = ttls.split(",")
    a_l = a.split(",") if a else []
    ns_l = ns.split(",") if ns else []
    ia = ins = 0

    for i in range(len(t)):
        tipo = tipos.get(t[i])
        if tipo is None:
            continue
        if tipo == "A":
            dato = a_l[ia] if ia < len(a_l) else "?"
            ia += 1
        elif tipo == "NS":
            dato = ns_l[ins] if ins < len(ns_l) else "?"
            ins += 1
        else:
            dato = (f"{mname} {rname} serial={serial} refresh={refresh} "
                    f"retry={retry} expire={expire} minimum={minimo}")
        clave = (src, n[i], tipo, l[i], dato)
        if clave in vistos:
            continue
        vistos.add(clave)
        print(f"{src:<14}{n[i]:<20}{tipo:<5}{l[i]:<8}{dato}")
