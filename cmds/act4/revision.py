import subprocess

zonas = [
    (".", "172.30.0.10"),
    ("unsigned", "172.30.0.20"),
    ("alpha.unsigned", "172.30.0.21"),
    ("delta.unsigned", "172.30.0.22"),
    ("eta.unsigned", "172.30.0.23"),
    ("iota.unsigned", "172.30.0.24"),
    ("signed", "172.30.0.40"),
    ("beta.signed", "172.30.0.41"),
    ("gamma.signed", "172.30.0.42"),
    ("zeta.signed", "172.30.0.43"),
    ("theta.signed", "172.30.0.44"),
    ("kappa.signed", "172.30.0.45"),
    ("test", "172.30.0.30"),
    ("badalg.test", "172.30.0.31"),
    ("expired.test", "172.30.0.32"),
    ("nods.test", "172.30.0.33"),
    ("walkable.test", "172.30.0.34"),
]


def dig(ip, nombre, tipo):
    cmd = f"dig @{ip} {nombre} {tipo} +dnssec +multiline"
    return subprocess.run(cmd.split(), capture_output=True, text=True).stdout


def revisar_dnskey(texto):
    algoritmos_validos = [8, 13, 14]
    encontrado = False
    for linea in texto.splitlines():
        if "DNSKEY" in linea and ("257" in linea or "256" in linea):
            alg = int(linea.split()[6])
            encontrado = True
            print(f"  DNSKEY algoritmo {alg} -> {'VALIDO' if alg in algoritmos_validos else 'NO AUTORIZADO'}")
    if not encontrado:
        print("  Sin DNSKEY (zona no firmada)")


def revisar_rrsig(texto):
    for linea in texto.splitlines():
        if "RRSIG" in linea:
            partes = linea.split()
            if len(partes) > 10:
                print(f"  RRSIG cubre {partes[4]}, expira {partes[8]}, firmo key tag {partes[10]}")


def revisar_ttl(texto):
    vistos = set()
    for linea in texto.splitlines():
        partes = linea.split()
        if len(partes) >= 4 and partes[1].isdigit() and partes[2] == "IN":
            clave = (partes[3], partes[1])
            if clave not in vistos:
                vistos.add(clave)
                print(f"  TTL de {partes[3]}: {partes[1]}s")


def revisar_nsec(ip, nombre):
    texto = dig(ip, f"noexiste.{nombre}", "A")
    if "NSEC3" in texto:
        print("  Usa NSEC3 (seguro contra zone walking)")
    elif "NSEC" in texto:
        print("  Usa NSEC (VULNERABLE a zone walking)")
    else:
        print("  Sin NSEC/NSEC3 (zona no firmada)")


def revisar_cadena(nombre):
    texto = dig("172.30.0.101", nombre, "DNSKEY")
    if "SERVFAIL" in texto:
        print("  Cadena ROTA (SERVFAIL)")
    elif " ad;" in texto or " ad " in texto:
        print("  Cadena VALIDA (ad presente)")
    else:
        print("  Delegacion insegura (sin ad, sin error)")


def main():
    for nombre, ip in zonas:
        print(f"\n=== {nombre} ===")
        texto = dig(ip, nombre, "DNSKEY")
        revisar_dnskey(texto)
        revisar_rrsig(texto)
        revisar_ttl(texto)
        revisar_nsec(ip, nombre)
        revisar_cadena(nombre)


if __name__ == "__main__":
    main()
