# firewall-security-rules

Script único de RouterOS v7 que **detecta escaneos de puertos y fuerza bruta en FILTER** (con estado)
y **bloquea en RAW** (antes de conntrack, sin coste para la tabla de conexiones).
Se instala sobre la configuración por defecto (`defconf`) sin sustituirla.

| Archivo | Función |
|---|---|
| `fsr.rsc` | Instalador idempotente con bloque de configuración y módulos activables |
| `fsr-uninstall.rsc` | Elimina todo lo que lleva `comment="FSR: ..."` y las listas `fsr_*` |
| `clients/knock.sh`, `clients/knock.ps1` | Clientes de port knocking |

## Diseño

```
WAN ─► RAW prerouting ──► conntrack ──► FILTER input ──► defconf "drop all not coming from LAN"
        │ fsr_trusted → accept          │ PSD TCP/UDP      → fsr_scanners (1d)
        │ fsr_scanners → DROP           │ honeyports       → fsr_scanners (1w)
        │ bogons / not-global → DROP    │ bruteforce 5m/15m/1h → fsr_bf_blacklist (1d)
        │ flags TCP imposibles          │ port knocking (opcional)
        │   → fsr_scanners (1h) + DROP  │
```

- **Timeouts según la fiabilidad de la señal**: los flags TCP inválidos se pueden falsificar sin handshake,
  así que su bloqueo dura poco (1h). PSD y los puertos trampa requieren paquetes `new` reales, así que el bloqueo dura más.
- **`fsr_trusted`** nunca se marca ni se bloquea. Rellénalo **antes** de instalar.
- **Tag `FSR:`** en todas las reglas (mismo patrón que `defconf:`). Permite reinstalar, desinstalar y auditar sin tocar el resto.
- **Default-deny**: no se bloquea puerto a puerto. La defconf ya descarta todo lo que no viene de la LAN; FSR solo añade detección y bloqueo previo.

## Instalación

1. Edita el bloque `CONFIGURACION` al principio de `fsr.rsc` (mínimo: `trusted4`).
   Con `interactive true` (por defecto), el script pregunta en pantalla `s/n` cada módulo y cada ajuste de hardening
   (IP Cloud incluido). Si pulsas Enter o pasan 120 s sin respuesta, se aplica el valor del bloque de configuración.
   Al final pide confirmación y, si respondes `n`, sale sin tocar nada. Para un despliegue desatendido, pon `interactive false`.
2. Sube **los dos** `.rsc` a `/file` (WinBox → Files o `scp`).
3. Activa **Safe Mode** (Ctrl+X en el terminal).
4. Ejecuta:
   ```routeros
   /import file-name=fsr.rsc verbose=yes
   ```
5. Comprueba que sigues teniendo acceso y **confirma** antes de que pase `rollback` (5 min por defecto):
   ```routeros
   :global fsrConfirmed true
   ```
   Si no confirmas, el router ejecuta `fsr-uninstall.rsc` solo. Antes de cambiar nada se guarda un `/export` en `fsr-pre-install.rsc`.

## Módulos

| Variable | Por defecto | Qué hace |
|---|---|---|
| `modRaw` | true | Bloqueo en RAW y flags TCP imposibles (NULL, SYN+FIN, Xmas…) |
| `modBogons` | true | Descarta bogons RFC 6890; omite `not_global` si la WAN tiene IP privada/CGNAT |
| `modScan` | true | PSD TCP/UDP y puertos trampa (`honeyPorts`) |
| `modForward` | true | `no_forward` y `!dstnat` si la defconf no los tiene |
| `modIPv6` | true | Lo mismo en `/ipv6 firewall` (listas `fsr_*6`) |
| `modHardening` | true | Servicios según *Securing your router* (no se revierte al desinstalar) |
| `modBruteforce` | true | Listas escalonadas sobre `bfPorts` |
| `modKnock` | **false** | Port knocking de 3 golpes con reset ante un puerto erróneo |

Opciones sensibles, **desactivadas por defecto** para no dejarte sin acceso:
- `restrictServices`: limita `/ip service` a `mgmtNets`.
- `disableCloud`: apaga DDNS (rompe endpoints `*.sn.mynetname.net`).

MAC-WinBox y neighbor discovery quedan limitados a la LAN, no a `none`, para conservar el acceso de rescate por capa 2.

## Operación

```routeros
/ip firewall address-list print where list~"^fsr_"
/ip firewall raw print stats where comment~"^FSR:"
/ip firewall filter print stats where comment~"^FSR:"
/log print where message~"FSR-"
/ip firewall address-list remove [find where list=fsr_scanners address=1.2.3.4]   # desbloquear
```

Prefijos de log para el SIEM: `FSR-SCAN-FLAGS`, `FSR-SCAN-PSD`, `FSR-HONEY`, `FSR-BF`, `FSR-KNOCK-OK`, `FSR-KNOCK-FAIL` (y sus variantes `*6`).

## Port knocking

Actívalo con `modKnock true`. Usa una secuencia **no ascendente** propia:
```bash
./clients/knock.sh mi.ip.publica 48211 9337 29004 && ssh usuario@mi.ip.publica
```
El port knocking es ocultación, no autenticación. Para acceso remoto real usa **WireGuard**.

## Pruebas

**Siempre desde un host externo** (VPS). Escanear tu propia IP pública desde la LAN pasa por el router (hairpin) y te bloquea a ti.

| Prueba | Comando | Resultado esperado |
|---|---|---|
| NULL / FIN / Xmas | `nmap -sN` / `-sF` / `-sX -p1-100 <WAN>` | IP en `fsr_scanners` (1h), log `FSR-SCAN-FLAGS` |
| SYN | `nmap -sS -p1-1000 <WAN>` | log `FSR-SCAN-PSD`, timeout 1d |
| Puerto trampa | `nc -zv <WAN> 3389` | log `FSR-HONEY`, timeout 1w |
| Idempotencia | importar dos veces | mismo número de reglas `FSR:` |
| Desinstalación | `fsr-uninstall.rsc` | 0 reglas `FSR:` |

## Fuentes

- MikroTik: [Securing your router](https://help.mikrotik.com/docs/spaces/ROS/pages/328353/Securing+your+router), [Building Advanced Firewall](https://help.mikrotik.com/docs/spaces/ROS/pages/328513/Building+Advanced+Firewall), [Bruteforce prevention](https://help.mikrotik.com/docs/spaces/ROS/pages/268337176/Bruteforce+prevention), [Port knocking](https://help.mikrotik.com/docs/spaces/ROS/pages/154042369/Port+knocking)
- [Essential MikroTik WAN Security](https://freedium-mirror.cfd/https://medium.com/@muhiminulhasan.me/essential-mikrotik-wan-security-a-beginners-hardening-guide-26e987c5c66a), como checklist de servicios

## Licencia

MIT
