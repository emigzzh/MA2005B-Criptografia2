#!/usr/bin/env python3
# Uso: python3 resumen-lab3.py traza.pcap ["filtro extra, ej. ip.src==172.30.0.101"]
import subprocess, sys

pcap = sys.argv[1]
extra = f" && ({sys.argv[2]})" if len(sys.argv) > 2 else ""
T = {"1": "A", "2": "NS", "6": "SOA", "28": "AAAA", "43": "DS", "46": "RRSIG",
     "47": "NSEC", "48": "DNSKEY", "50": "NSEC3", "51": "NSEC3PARAM"}
RC = {"0": "OK", "2": "SERVFAIL", "3": "NXDOMAIN", "5": "REFUSED"}
F = ["frame.number", "ip.src", "ip.dst", "dns.qry.name", "dns.qry.type",
     "dns.flags.rcode", "dns.flags.authenticated", "dns.resp.type", "dns.resp.ttl",
     "dns.rrsig.key_tag", "dns.dnskey.flags", "dns.nsec3.iterations"]

sh = lambda c: subprocess.run(c, capture_output=True, text=True).stdout
known = {l.split("\t")[2] for l in sh(["tshark", "-G", "fields"]).splitlines() if l.count("\t") > 1}
F = [f for f in F if f in known]

cmd = ["tshark", "-r", pcap, "-Y", "dns.flags.response==1" + extra, "-T", "fields",
       "-E", "separator=|", "-E", "occurrence=a", "-E", "aggregator=,"]
for f in F:
    cmd += ["-e", f]

for line in sh(cmd).splitlines():
    v = line.split("|") + [""] * len(F)
    d = dict(zip(F, v))
    g = lambda k: d.get(k, "")
    # Registros: tipo/TTL, agrupando repetidos (RRSIGx2/86400)
    cuenta = {}
    for t, l in zip(g("dns.resp.type").split(","), g("dns.resp.ttl").split(",")):
        if t:
            cuenta[(T.get(t, t), l)] = cuenta.get((T.get(t, t), l), 0) + 1
    rr = " ".join(f"{t}{'x'+str(n) if n > 1 else ''}/{l}" for (t, l), n in cuenta.items())
    # Extras: key tags, flags DNSKEY, iteraciones NSEC3
    ex = []
    if g("dns.rrsig.key_tag"):
        ex.append("tag:" + ",".join(sorted(set(g("dns.rrsig.key_tag").split(",")))))
    if g("dns.dnskey.flags"):
        ex.append("flags:" + ",".join(sorted(set(g("dns.dnskey.flags").split(",")))))
    if g("dns.nsec3.iterations"):
        ex.append("it:" + ",".join(sorted(set(g("dns.nsec3.iterations").split(",")))))
    src = g("ip.src").replace("172.30.0.", ".")
    dst = g("ip.dst").replace("172.30.0.", ".")
    print(f"{g('frame.number'):>4} {src}>{dst} {g('dns.qry.name') or '.'} "
          f"{T.get(g('dns.qry.type'), g('dns.qry.type'))} "
          f"{RC.get(g('dns.flags.rcode'), g('dns.flags.rcode'))} "
          f"{'AD' if g('dns.flags.authenticated') == '1' else '-'} | {rr} | {' '.join(ex)}")
