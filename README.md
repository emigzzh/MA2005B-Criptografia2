# MA2005B-Criptografia2

Laboratorio de pruebas para DNSSEC. Árbol DNS propio y aislado, construido con BIND9 sobre una máquina virtual Ubuntu, protegido con DNSSEC y auditado con una herramienta de verificación.

Proyecto del Equipo 4 de la materia MA2005B, Aplicación de criptografía y seguridad, del Instituto Tecnológico y de Estudios Superiores de Monterrey. Socio formador: NIC México.

## Contenido del repositorio

```
.
├── dns/    Una carpeta por servidor, con su named.conf y su carpeta zones/
├── cmds/   Scripts de arranque, consulta y verificación
└── README.md
```

### dns/

Cada subcarpeta corresponde a un servidor (por ejemplo `root`, `unsigned`, `alpha`, `signed`, `beta`, `test`, `badalg`, `recursive1`, `recursive2`) y contiene:

- `named.conf`: configuración de esa instancia de BIND.
- `zones/`: archivo de zona, y en las zonas firmadas, las llaves (`.key` y `.private`), el archivo de zona firmada (`.signed`) y los DS (`dsset-...`).

### cmds/

- `init.sh`: levanta todo el laboratorio. Detiene instancias previas, da de alta las direcciones en la interfaz de loopback, arranca cada instancia de `named` y verifica que todas escuchan en el puerto 53 por TCP y UDP.
- `act4/revision.py`: herramienta de verificación de las 17 zonas.
- `act4/consulta1.sh`: consultas de verificación con `dig`.

## Arquitectura

Cada servidor es una instancia independiente de `named`, con su propio archivo de configuración y una dirección distinta del segmento `172.30.0.0/24`, asignada a la interfaz `lo` con máscara `/32`. El árbol tiene una raíz propia, tres dominios de nivel superior y dominios hijos, para un total de 17 zonas y 2 recursivos.

| IP | Servidor | Función |
|---|---|---|
| 172.30.0.10 | root | Raíz, firmada |
| 172.30.0.20 | unsigned | TLD sin firmar |
| 172.30.0.21 | alpha | Hijo de unsigned |
| 172.30.0.22 | delta | Hijo de unsigned |
| 172.30.0.23 | eta | Hijo de unsigned |
| 172.30.0.24 | iota | Hijo de unsigned |
| 172.30.0.30 | test | TLD firmado |
| 172.30.0.31 | badalg | Hijo de test, algoritmo 99 |
| 172.30.0.32 | expired | Hijo de test, firmas vencidas |
| 172.30.0.33 | nods | Hijo de test, sin DS |
| 172.30.0.34 | walkable | Hijo de test, con NSEC |
| 172.30.0.40 | signed | TLD firmado |
| 172.30.0.41 | beta | Hijo de signed, firmado |
| 172.30.0.42 | gamma | Hijo de signed, sin firmar |
| 172.30.0.43 | zeta | Hijo de signed, firmado |
| 172.30.0.44 | theta | Hijo de signed, firmado |
| 172.30.0.45 | kappa | Hijo de signed, sin firmar |
| 172.30.0.100 | recursive1 | Recursivo sin validación |
| 172.30.0.101 | recursive2 | Recursivo con validación |

Jerarquía:

- Raíz (`.`): delega `unsigned`, `signed` y `test`.
- `unsigned`: sin firmar. Hijos: `alpha`, `delta`, `eta`, `iota`.
- `signed`: firmado. Hijos: `beta`, `zeta`, `theta` (firmados) y `gamma`, `kappa` (sin firmar).
- `test`: firmado. Hijos con fallas intencionales: `badalg`, `expired`, `nods`, `walkable`.

`recursive1` funciona sin validación y `recursive2` con validación DNSSEC y la KSK de la raíz como trust anchor.

## Parámetros de DNSSEC

- Algoritmo 13 (ECDSAP256SHA256) para llaves y firmas.
- NSEC3 sin salt y con cero iteraciones adicionales (`dnssec-signzone -S -3 - -H 0`).
- El DS de cada zona hija se publica en la zona del padre mediante `$INCLUDE dsset-<zona>.`.
- Excepción deliberada: `walkable.test` usa NSEC para demostrar el zone walking.

## Zonas con errores controlados (bajo test)

| Zona | Error introducido | Resultado en recursive2 |
|---|---|---|
| badalg.test | Algoritmo de los DNSKEY cambiado a 99; el DS original sigue publicado | SERVFAIL |
| expired.test | Firmas RRSIG con fechas vencidas | SERVFAIL |
| nods.test | Zona firmada, pero sin DS en el padre | Resuelve sin la bandera `ad` (insegura) |
| walkable.test | Firmada con NSEC en lugar de NSEC3 | Válida y enumerable |

## Requisitos

- Ubuntu con BIND9 y utilidades: `sudo apt install bind9 bind9utils dnsutils -y`.
- Para las capturas de tráfico y su análisis: `tcpdump`, `tshark` y Python 3.
- Permisos de administrador (`sudo`).

## Cómo reproducir el laboratorio

Para cada servidor `<nombre>`, con su dirección `172.30.0.<X>` de la tabla anterior:

```bash
sudo cp dns/<nombre>/named.conf /etc/bind/named.conf.<nombre>
sudo cp dns/<nombre>/zones/db.<zona>[.signed] /var/lib/bind/
sudo chown bind:bind /var/lib/bind/db.<zona>[.signed]
sudo named-checkconf /etc/bind/named.conf.<nombre>
sudo ip addr add 172.30.0.<X>/32 dev lo
sudo named -4 -u bind -c /etc/bind/named.conf.<nombre>
sudo ss -tulpn | grep 172.30.0.<X>:53
```

`recursive1` usa el `named.conf` principal y se reinicia como servicio del sistema: `sudo systemctl restart named`.

Una vez instalados los archivos, `cmds/init.sh` automatiza el alta de direcciones, el arranque y la verificación de todas las instancias. Las direcciones de loopback no persisten tras reiniciar la máquina, por lo que hay que volver a ejecutarlo.

## Verificación

Consulta a los dos recursivos con y sin validación:

```bash
dig @172.30.0.100 www.beta.signed        # sin validación: sin la bandera ad
dig @172.30.0.101 www.beta.signed        # con validación: con la bandera ad
dig @172.30.0.101 www.badalg.test        # SERVFAIL
dig @172.30.0.101 www.nods.test          # resuelve, sin ad
python3 cmds/act4/revision.py            # resumen de las 17 zonas
```

Resultado esperado de `revision.py`: 7 zonas con cadena válida (raíz, signed, beta, zeta, theta, test y walkable), 8 delegaciones inseguras y 2 zonas con la cadena rota (badalg y expired).

## Aviso sobre las llaves

Las carpetas `zones/` incluyen llaves privadas (`.private`). Son llaves de un laboratorio aislado, generadas únicamente para este proyecto, y no protegen ningún sistema real.

## Equipo 4

- Emilio Alejandro González Huerta (A01286440)
- Laurie Camila Hernández Pacheco (A01286569)
- Angel Everardo Rodríguez Guevara (A01286630)
- Emiliano Hervert de la Cruz (A01412606)
- Fernando Álvarez Ruiz (A01286754)

Profesor: Alberto F. Martínez. Socio formador: NIC México, César Steve Salas S.
