# =============================================================================
#  fsr.rsc - firewall-security-rules v2.0 (script unico)
#  https://github.com/410g0n3/firewall-security-rules
#
#  Deteccion en FILTER (con estado) -> marca IP en address-list
#  Ejecucion en RAW (sin estado, antes de conntrack) -> drop barato
#
#  Requisitos : RouterOS v7, interface-lists WAN y LAN definidas.
#  Instalacion: subir fsr.rsc + fsr-uninstall.rsc, activar Safe Mode (Ctrl+X) y
#               /import file-name=fsr.rsc verbose=yes
#  Idempotente: todo lo que crea lleva comment "FSR: ..." o list "fsr_*";
#               reimportar borra y recrea (conserva las IPs ya detectadas).
#  Bibliografia: MikroTik docs - Securing your router, Building Advanced
#               Firewall, Bruteforce prevention, Port knocking.
# =============================================================================
{
# ============================ CONFIGURACION ==================================
# interactive=true: pregunta en pantalla cada modulo/ajuste (s/n). Los valores de
# abajo son la respuesta por defecto (Enter o sin respuesta en 120s).
:local interactive true

:local wanList "WAN"
:local lanList "LAN"

# IPs que nunca se marcan ni bloquean (equipo de gestion, VPS de monitorizacion...)
:local trusted4 {"192.168.78.140"}
:local trusted6 [:toarray ""]

# --- Modulos ---
:local modRaw true
:local modBogons true
:local modScan true
:local modForward true
:local modIPv6 true
:local modHardening true
:local modBruteforce true
:local modKnock false

# --- Hardening (cada ajuste por separado) ---
:local hMacServer true
:local hNeighbor true
:local hBtest true
:local hProxy true
:local hSocks true
:local hUpnp true
:local hSsh true
:local hRomon true
:local hServices true
# disableCloud=true apaga DDNS/update-time de IP Cloud (no si usas Back To Home o *.sn.mynetname.net)
:local disableCloud false
# restrictServices=true limita /ip service a mgmtNets (riesgo de lockout si gestionas por VPN)
:local restrictServices false
:local mgmtNets "192.168.78.0/24"

# --- Deteccion de escaneos ---
# Timeouts segun fiabilidad de la senal (flags TCP se pueden falsificar -> corto)
:local tFlags 1h
:local tPsd 1d
:local tHoney 1w
:local honeyPorts "23,445,1433,3389,5900"

# --- Bruteforce (listas escalonadas 5m/15m/1h -> blacklist 1d) ---
# Ojo: WinBox (8291) abre varias conexiones por sesion; anadelo solo con trusted4 bien relleno
:local bfPorts "22"

# --- Port knocking (modKnock) ---
# Secuencia NO ascendente y no contigua: un barrido secuencial no debe completarla
:local knockPorts {48211;9337;29004}
:local knockServices "22,8291"
:local knockStep 15s
:local knockTime 30m

# --- Logging remoto (Wazuh/syslog). "" = desactivado ---
:local logRemote ""
:local logRemotePort 514

# --- Rollback automatico si no confirmas (requiere fsr-uninstall.rsc en /file). 0s = off ---
:local rollback 5m
# =============================================================================


# ---------------------------- comprobaciones ---------------------------------
:local ver [/system resource get version]
:if ([:pick $ver 0 1] != "7") do={ :error ("FSR: requiere RouterOS v7 (detectado " . $ver . ")") }
:if ([:len [/interface list find where name=$wanList]] = 0) do={ :error ("FSR: no existe la interface-list " . $wanList) }
:if ([:len [/interface list find where name=$lanList]] = 0) do={ :error ("FSR: no existe la interface-list " . $lanList) }
:put ("FSR: RouterOS " . $ver . " - WAN=" . $wanList . " LAN=" . $lanList)

# version menor (7.xx) para valores que cambian entre versiones
:local rest [:pick $ver 2 [:len $ver]]
:local num ""
:local i 0
:while (($i < [:len $rest]) && ([:pick $rest $i] ~ "^[0-9]\$")) do={ :set num ($num . [:pick $rest $i]); :set i ($i + 1) }
:local minor [:tonum $num]

# ---------------------------- preguntas --------------------------------------
# $ask "texto" <defecto bool> -> bool.  s/y = si, n = no, Enter/timeout = defecto
:local ask do={
  :local d ([:tostr $2] = "true")
  :local ds "n"
  :if ($d) do={ :set ds "s" }
  :put ("  ? " . $1 . "  [s/n, Enter=" . $ds . "]")
  :local k 65535
  :do { :set k [/terminal inkey timeout=120] } on-error={ :set k 65535 }
  :if (($k = 115) || ($k = 83) || ($k = 121) || ($k = 89)) do={ :put "    -> si"; :return true }
  :if (($k = 110) || ($k = 78)) do={ :put "    -> no"; :return false }
  :put ("    -> " . $ds . " (por defecto)")
  :return $d
}

:if ($interactive) do={
  :put ""
  :put "FSR: ===== seleccion de modulos ====="
  :set modRaw [$ask "RAW: bloqueo de escaneres y flags TCP imposibles antes de conntrack" $modRaw]
  :if ($modRaw) do={ :set modBogons [$ask "RAW: descartar bogons RFC6890 (src invalido / no global desde WAN)" $modBogons] }
  :set modScan [$ask "FILTER: detectar escaneos (PSD TCP/UDP + honeyports)" $modScan]
  :set modForward [$ask "FILTER forward: drop no_forward (incluye multicast 224/4 -> NO si tienes IPTV)" $modForward]
  :set modIPv6 [$ask "IPv6: mismas protecciones en /ipv6 firewall" $modIPv6]
  :set modBruteforce [$ask ("Bruteforce escalonado en puertos " . $bfPorts . " (tambien afecta a la LAN salvo trusted)") $modBruteforce]
  :set modKnock [$ask "Port knocking (abre servicios tras la secuencia)" $modKnock]
  :set modHardening [$ask "Hardening de servicios del router (se pregunta cada ajuste)" $modHardening]
  :if ($modHardening) do={
    :put "FSR: ----- hardening -----"
    :set hMacServer [$ask "MAC-Telnet off, MAC-WinBox solo LAN, MAC-ping off" $hMacServer]
    :set hNeighbor [$ask "Neighbor discovery solo en LAN" $hNeighbor]
    :set hBtest [$ask "Bandwidth-test server off" $hBtest]
    :set hProxy [$ask "Web proxy off" $hProxy]
    :set hSocks [$ask "SOCKS off" $hSocks]
    :set hUpnp [$ask "UPnP off" $hUpnp]
    :set hSsh [$ask "SSH strong-crypto" $hSsh]
    :set hRomon [$ask "RoMON off" $hRomon]
    :set hServices [$ask "Desactivar servicios telnet, ftp, www (80), api (8728)" $hServices]
    :set disableCloud [$ask "IP Cloud: desactivar DDNS y update-time" $disableCloud]
    :set restrictServices [$ask ("Restringir /ip service a " . $mgmtNets . " (riesgo de lockout)") $restrictServices]
  }
  :if ($modKnock) do={ :put ("FSR: knock " . [:tostr $knockPorts] . " -> " . $knockServices) }
  :put ""
  :if (![$ask "Aplicar ahora la seleccion" true]) do={ :error "FSR: cancelado por el usuario, no se ha modificado nada" }
}

# ---------------------------- copia previa -----------------------------------
:do { /export file=fsr-pre-install } on-error={ :put "FSR: AVISO no se pudo exportar la configuracion previa" }
:put "FSR: export previo en fsr-pre-install.rsc"

# ---------------------------- rollback ---------------------------------------
:if ($rollback > 0s) do={
  :local uf [/file find where name~"fsr-uninstall.rsc"]
  :if ([:len $uf] > 0) do={
    :local ufn [/file get [:pick $uf 0] name]
    :global fsrConfirmed false
    :execute script=(":delay " . $rollback . "; :global fsrConfirmed; :if (\$fsrConfirmed != true) do={ :log warning \"FSR: instalacion no confirmada, rollback\"; /import file-name=" . $ufn . " }")
    :put ("FSR: ROLLBACK ARMADO en " . $rollback . ". Confirma con:  :global fsrConfirmed true")
  } else={
    :put "FSR: AVISO sin fsr-uninstall.rsc en /file no hay rollback automatico: usa Safe Mode"
  }
}

# ---------------------------- limpieza (idempotencia) ------------------------
/ip firewall filter remove [find where comment~"^FSR:"]
/ip firewall raw remove [find where comment~"^FSR:"]
/ip firewall address-list remove [find where list~"^fsr_" && !dynamic]
/ipv6 firewall filter remove [find where comment~"^FSR:"]
/ipv6 firewall raw remove [find where comment~"^FSR:"]
/ipv6 firewall address-list remove [find where list~"^fsr_" && !dynamic]
/system logging remove [find where action="fsr-remote"]
/system logging action remove [find where name="fsr-remote"]
:put "FSR: limpieza previa hecha (IPs detectadas conservadas)"

# ---------------------------- address-lists ----------------------------------
:foreach a in=$trusted4 do={ /ip firewall address-list add list=fsr_trusted address=$a comment="FSR: trusted" }
:foreach a in=$trusted6 do={ /ipv6 firewall address-list add list=fsr_trusted6 address=$a comment="FSR: trusted" }

:foreach p in={"127.0.0.0/8";"192.0.0.0/24";"192.0.2.0/24";"198.51.100.0/24";"203.0.113.0/24";"240.0.0.0/4"} do={
  /ip firewall address-list add list=fsr_bad_ipv4 address=$p comment="FSR: RFC6890 bad"
}
:foreach p in={"0.0.0.0/8";"10.0.0.0/8";"100.64.0.0/10";"169.254.0.0/16";"172.16.0.0/12";"192.0.0.0/29";"192.168.0.0/16";"198.18.0.0/15"} do={
  /ip firewall address-list add list=fsr_not_global_ipv4 address=$p comment="FSR: RFC6890 not global"
}
:foreach p in={"0.0.0.0/8";"169.254.0.0/16";"224.0.0.0/4";"255.255.255.255/32"} do={
  /ip firewall address-list add list=fsr_no_forward_ipv4 address=$p comment="FSR: RFC6890 no forward"
}

# WAN con IP privada/CGNAT (doble NAT, ONT en modo router) -> no filtrar not_global desde WAN
:local wanPrivate false
:foreach m in=[/interface list member find where list=$wanList] do={
  :local ifn [/interface list member get $m interface]
  :foreach a in=[/ip address find where interface=$ifn] do={
    :local ad [/ip address get $a address]
    :local ip [:toip [:pick $ad 0 [:find $ad "/"]]]
    :if (($ip in 10.0.0.0/8) || ($ip in 172.16.0.0/12) || ($ip in 192.168.0.0/16) || ($ip in 100.64.0.0/10)) do={ :set wanPrivate true }
  }
}
:if ($wanPrivate) do={ :put "FSR: AVISO WAN con IP privada/CGNAT: se omite el drop de not_global desde WAN" }


# ============================ RAW (ejecucion) ================================
:if ($modRaw) do={
:do {
  :local rawIds [/ip firewall raw find]
  :if ([:len $rawIds] > 0) do={
    /ip firewall raw add chain=prerouting action=passthrough disabled=yes comment="FSR: anchor raw" place-before=[:pick $rawIds 0]
  } else={
    /ip firewall raw add chain=prerouting action=passthrough disabled=yes comment="FSR: anchor raw"
  }
  :local ra [:pick [/ip firewall raw find where comment="FSR: anchor raw"] 0]

  /ip firewall raw add chain=prerouting action=accept src-address-list=fsr_trusted comment="FSR: trusted bypass" place-before=$ra
  /ip firewall raw add chain=prerouting action=accept in-interface-list=$wanList protocol=udp src-port=67 dst-port=68 comment="FSR: accept DHCP del ISP (puede venir de IP privada)" place-before=$ra
  /ip firewall raw add chain=prerouting action=drop in-interface-list=$wanList src-address-list=fsr_scanners comment="FSR: drop scanners" place-before=$ra
  :if ($modBogons) do={
    /ip firewall raw add chain=prerouting action=drop src-address-list=fsr_bad_ipv4 comment="FSR: drop bogon src" place-before=$ra
    :if (!$wanPrivate) do={
      /ip firewall raw add chain=prerouting action=drop in-interface-list=$wanList src-address-list=fsr_not_global_ipv4 comment="FSR: drop not-global from WAN" place-before=$ra
    }
  }
  /ip firewall raw add chain=prerouting action=drop in-interface-list=$wanList protocol=udp port=0 comment="FSR: drop UDP port 0" place-before=$ra
  /ip firewall raw add chain=prerouting action=jump jump-target=fsr-bad-tcp in-interface-list=$wanList protocol=tcp comment="FSR: jump bad-tcp" place-before=$ra

  /ip firewall raw add chain=fsr-bad-tcp action=jump jump-target=fsr-tag protocol=tcp tcp-flags=!fin,!syn,!rst,!ack comment="FSR: NULL scan"
  /ip firewall raw add chain=fsr-bad-tcp action=jump jump-target=fsr-tag protocol=tcp tcp-flags=fin,syn comment="FSR: SYN+FIN"
  /ip firewall raw add chain=fsr-bad-tcp action=jump jump-target=fsr-tag protocol=tcp tcp-flags=fin,rst comment="FSR: FIN+RST"
  /ip firewall raw add chain=fsr-bad-tcp action=jump jump-target=fsr-tag protocol=tcp tcp-flags=fin,!ack comment="FSR: FIN sin ACK"
  /ip firewall raw add chain=fsr-bad-tcp action=jump jump-target=fsr-tag protocol=tcp tcp-flags=fin,urg comment="FSR: FIN+URG Xmas"
  /ip firewall raw add chain=fsr-bad-tcp action=jump jump-target=fsr-tag protocol=tcp tcp-flags=syn,rst comment="FSR: SYN+RST"
  /ip firewall raw add chain=fsr-bad-tcp action=jump jump-target=fsr-tag protocol=tcp tcp-flags=rst,urg comment="FSR: RST+URG"
  /ip firewall raw add chain=fsr-bad-tcp action=drop protocol=tcp port=0 comment="FSR: TCP port 0"
  /ip firewall raw add chain=fsr-bad-tcp action=return comment="FSR: bad-tcp return"

  /ip firewall raw add chain=fsr-tag action=add-src-to-address-list address-list=fsr_scanners address-list-timeout=$tFlags log=yes log-prefix="FSR-SCAN-FLAGS" comment="FSR: tag flags (timeout corto, spoofable)"
  /ip firewall raw add chain=fsr-tag action=drop comment="FSR: drop flags"
  :put "FSR: [ok] RAW"
} on-error={ :put "FSR: [ERROR] modulo RAW"; :log error "FSR: fallo modulo RAW" }
}


# ============================ FILTER input (deteccion) =======================
# Ancla justo antes del default-deny de la defconf ("drop all not coming from LAN")
:local dd [/ip firewall filter find where chain=input && action=drop && comment~"not coming from LAN"]
:if ([:len $dd] > 0) do={
  /ip firewall filter add chain=input action=passthrough disabled=yes comment="FSR: anchor input" place-before=[:pick $dd 0]
} else={
  :put "FSR: AVISO no se detecta el default-deny defconf en input: reglas al final de la cadena"
  /ip firewall filter add chain=input action=passthrough disabled=yes comment="FSR: anchor input"
}
:local fa [:pick [/ip firewall filter find where comment="FSR: anchor input"] 0]

# ---- Bruteforce (orden inverso: un paquete solo avanza una fase) ----
:if ($modBruteforce) do={
:do {
  /ip firewall filter add chain=input action=drop protocol=tcp dst-port=$bfPorts src-address-list=fsr_bf_blacklist comment="FSR: BF drop blacklist" place-before=$fa
  /ip firewall filter add chain=input action=add-src-to-address-list address-list=fsr_bf_blacklist address-list-timeout=1d protocol=tcp dst-port=$bfPorts connection-state=new src-address-list=fsr_bf_stage3 log=yes log-prefix="FSR-BF" comment="FSR: BF stage3 -> blacklist" place-before=$fa
  /ip firewall filter add chain=input action=add-src-to-address-list address-list=fsr_bf_stage3 address-list-timeout=1h protocol=tcp dst-port=$bfPorts connection-state=new src-address-list=fsr_bf_stage2 comment="FSR: BF stage2 -> stage3" place-before=$fa
  /ip firewall filter add chain=input action=add-src-to-address-list address-list=fsr_bf_stage2 address-list-timeout=15m protocol=tcp dst-port=$bfPorts connection-state=new src-address-list=fsr_bf_stage1 comment="FSR: BF stage1 -> stage2" place-before=$fa
  /ip firewall filter add chain=input action=add-src-to-address-list address-list=fsr_bf_stage1 address-list-timeout=5m protocol=tcp dst-port=$bfPorts connection-state=new src-address-list=!fsr_trusted comment="FSR: BF new -> stage1" place-before=$fa
  :put ("FSR: [ok] Bruteforce puertos " . $bfPorts)
} on-error={ :put "FSR: [ERROR] modulo Bruteforce"; :log error "FSR: fallo modulo Bruteforce" }
}

# ---- Port knocking ----
:if ($modKnock) do={
:do {
  :local k1 [:pick $knockPorts 0]
  :local k2 [:pick $knockPorts 1]
  :local k3 [:pick $knockPorts 2]
  :local kl ($k1 . "," . $k2 . "," . $k3)
  :if (($k1 < $k2) && ($k2 < $k3)) do={ :put "FSR: AVISO secuencia de knock ascendente: un barrido secuencial podria completarla" }

  /ip firewall filter add chain=input action=accept in-interface-list=$wanList protocol=tcp dst-port=$knockServices src-address-list=fsr_knock_ok comment="FSR: knock accept servicios" place-before=$fa
  /ip firewall filter add chain=input action=jump jump-target=fsr-knock in-interface-list=$wanList protocol=tcp connection-state=new comment="FSR: knock jump" place-before=$fa

  /ip firewall filter add chain=fsr-knock action=return src-address-list=fsr_knock_fail comment="FSR: knock fallido reciente"
  /ip firewall filter add chain=fsr-knock action=add-src-to-address-list address-list=fsr_knock_ok address-list-timeout=$knockTime protocol=tcp dst-port=$k3 src-address-list=fsr_knock2 log=yes log-prefix="FSR-KNOCK-OK" comment="FSR: knock 3 -> ok"
  /ip firewall filter add chain=fsr-knock action=add-src-to-address-list address-list=fsr_knock2 address-list-timeout=$knockStep protocol=tcp dst-port=$k2 src-address-list=fsr_knock1 comment="FSR: knock 2"
  /ip firewall filter add chain=fsr-knock action=add-src-to-address-list address-list=fsr_knock1 address-list-timeout=$knockStep protocol=tcp dst-port=$k1 comment="FSR: knock 1"
  /ip firewall filter add chain=fsr-knock action=add-src-to-address-list address-list=fsr_knock_fail address-list-timeout=1m protocol=tcp dst-port=("!" . $kl) src-address-list=fsr_knock1 log=yes log-prefix="FSR-KNOCK-FAIL" comment="FSR: knock puerto erroneo fase1"
  /ip firewall filter add chain=fsr-knock action=add-src-to-address-list address-list=fsr_knock_fail address-list-timeout=1m protocol=tcp dst-port=("!" . $kl) src-address-list=fsr_knock2 log=yes log-prefix="FSR-KNOCK-FAIL" comment="FSR: knock puerto erroneo fase2"
  /ip firewall filter add chain=fsr-knock action=return comment="FSR: knock return"
  :put ("FSR: [ok] Port knocking " . $kl . " -> " . $knockServices)
} on-error={ :put "FSR: [ERROR] modulo Port knocking"; :log error "FSR: fallo modulo Port knocking" }
}

# ---- Deteccion de escaneos ----
:if ($modScan) do={
:do {
  /ip firewall filter add chain=input action=add-src-to-address-list address-list=fsr_scanners address-list-timeout=$tPsd protocol=tcp psd=21,3s,3,1 connection-state=new in-interface-list=$wanList src-address-list=!fsr_trusted log=yes log-prefix="FSR-SCAN-PSD" comment="FSR: PSD TCP" place-before=$fa
  /ip firewall filter add chain=input action=add-src-to-address-list address-list=fsr_scanners address-list-timeout=$tPsd protocol=udp psd=21,3s,3,1 connection-state=new in-interface-list=$wanList src-address-list=!fsr_trusted log=yes log-prefix="FSR-SCAN-PSD" comment="FSR: PSD UDP" place-before=$fa
  /ip firewall filter add chain=input action=add-src-to-address-list address-list=fsr_scanners address-list-timeout=$tHoney protocol=tcp dst-port=$honeyPorts connection-state=new in-interface-list=$wanList src-address-list=!fsr_trusted log=yes log-prefix="FSR-HONEY" comment="FSR: honeyports" place-before=$fa
  :if (!$modRaw) do={
    /ip firewall filter add chain=input action=drop in-interface-list=$wanList src-address-list=fsr_scanners comment="FSR: drop scanners (fallback sin RAW)" place-before=$fa
    :put "FSR: AVISO modRaw=false: el bloqueo se hace en FILTER (pasa por conntrack)"
  }
  :put "FSR: [ok] Deteccion de escaneos"
} on-error={ :put "FSR: [ERROR] modulo Scan"; :log error "FSR: fallo modulo Scan" }
}


# ============================ FILTER forward =================================
:if ($modForward) do={
:do {
  :local fi [/ip firewall filter find where chain=forward && comment~"drop invalid"]
  :local ff ""
  :if ([:len $fi] > 0) do={
    /ip firewall filter add chain=forward action=passthrough disabled=yes comment="FSR: anchor forward" place-before=[:pick $fi 0]
  } else={
    /ip firewall filter add chain=forward action=passthrough disabled=yes comment="FSR: anchor forward"
  }
  :set ff [:pick [/ip firewall filter find where comment="FSR: anchor forward"] 0]
  # Si usas IPTV multicast (p.ej. Movistar) desactiva estas dos reglas o quita 224.0.0.0/4 de fsr_no_forward_ipv4
  /ip firewall filter add chain=forward action=drop src-address-list=fsr_no_forward_ipv4 comment="FSR: drop bad forward src" place-before=$ff
  /ip firewall filter add chain=forward action=drop dst-address-list=fsr_no_forward_ipv4 comment="FSR: drop bad forward dst" place-before=$ff
  :if ([:len [/ip firewall filter find where chain=forward && comment~"DSTNAT"]] = 0) do={
    /ip firewall filter add chain=forward action=drop connection-state=new connection-nat-state=!dstnat in-interface-list=$wanList comment="FSR: drop WAN no DSTNAT"
    :put "FSR: anadido drop WAN no-DSTNAT (no existia el de defconf)"
  }
  :put "FSR: [ok] Forward"
} on-error={ :put "FSR: [ERROR] modulo Forward"; :log error "FSR: fallo modulo Forward" }
}


# ============================ IPv6 ===========================================
:if ($modIPv6) do={
:do {
  :local r6 [/ipv6 firewall raw find]
  :if ([:len $r6] > 0) do={
    /ipv6 firewall raw add chain=prerouting action=passthrough disabled=yes comment="FSR: anchor raw6" place-before=[:pick $r6 0]
  } else={
    /ipv6 firewall raw add chain=prerouting action=passthrough disabled=yes comment="FSR: anchor raw6"
  }
  :local ra6 [:pick [/ipv6 firewall raw find where comment="FSR: anchor raw6"] 0]
  /ipv6 firewall raw add chain=prerouting action=accept src-address-list=fsr_trusted6 comment="FSR: trusted6 bypass" place-before=$ra6
  /ipv6 firewall raw add chain=prerouting action=drop in-interface-list=$wanList src-address-list=fsr_scanners6 comment="FSR: drop scanners6" place-before=$ra6
  /ipv6 firewall raw add chain=prerouting action=jump jump-target=fsr-bad-tcp6 in-interface-list=$wanList protocol=tcp comment="FSR: jump bad-tcp6" place-before=$ra6
  /ipv6 firewall raw add chain=fsr-bad-tcp6 action=jump jump-target=fsr-tag6 protocol=tcp tcp-flags=!fin,!syn,!rst,!ack comment="FSR: NULL scan6"
  /ipv6 firewall raw add chain=fsr-bad-tcp6 action=jump jump-target=fsr-tag6 protocol=tcp tcp-flags=fin,syn comment="FSR: SYN+FIN6"
  /ipv6 firewall raw add chain=fsr-bad-tcp6 action=jump jump-target=fsr-tag6 protocol=tcp tcp-flags=fin,rst comment="FSR: FIN+RST6"
  /ipv6 firewall raw add chain=fsr-bad-tcp6 action=jump jump-target=fsr-tag6 protocol=tcp tcp-flags=fin,!ack comment="FSR: FIN sin ACK6"
  /ipv6 firewall raw add chain=fsr-bad-tcp6 action=jump jump-target=fsr-tag6 protocol=tcp tcp-flags=fin,urg comment="FSR: Xmas6"
  /ipv6 firewall raw add chain=fsr-bad-tcp6 action=jump jump-target=fsr-tag6 protocol=tcp tcp-flags=syn,rst comment="FSR: SYN+RST6"
  /ipv6 firewall raw add chain=fsr-bad-tcp6 action=return comment="FSR: bad-tcp6 return"
  /ipv6 firewall raw add chain=fsr-tag6 action=add-src-to-address-list address-list=fsr_scanners6 address-list-timeout=$tFlags log=yes log-prefix="FSR-SCAN6-FLAGS" comment="FSR: tag6 flags"
  /ipv6 firewall raw add chain=fsr-tag6 action=drop comment="FSR: drop6 flags"

  :local d6 [/ipv6 firewall filter find where chain=input && action=drop && comment~"not coming from LAN"]
  :if ([:len $d6] > 0) do={
    /ipv6 firewall filter add chain=input action=passthrough disabled=yes comment="FSR: anchor input6" place-before=[:pick $d6 0]
  } else={
    :put "FSR: AVISO no se detecta default-deny IPv6 en input"
    /ipv6 firewall filter add chain=input action=passthrough disabled=yes comment="FSR: anchor input6"
  }
  :local fa6 [:pick [/ipv6 firewall filter find where comment="FSR: anchor input6"] 0]
  /ipv6 firewall filter add chain=input action=add-src-to-address-list address-list=fsr_scanners6 address-list-timeout=$tPsd protocol=tcp psd=21,3s,3,1 connection-state=new in-interface-list=$wanList src-address-list=!fsr_trusted6 log=yes log-prefix="FSR-SCAN6-PSD" comment="FSR: PSD6 TCP" place-before=$fa6
  /ipv6 firewall filter add chain=input action=add-src-to-address-list address-list=fsr_scanners6 address-list-timeout=$tPsd protocol=udp psd=21,3s,3,1 connection-state=new in-interface-list=$wanList src-address-list=!fsr_trusted6 log=yes log-prefix="FSR-SCAN6-PSD" comment="FSR: PSD6 UDP" place-before=$fa6
  /ipv6 firewall filter add chain=input action=add-src-to-address-list address-list=fsr_scanners6 address-list-timeout=$tHoney protocol=tcp dst-port=$honeyPorts connection-state=new in-interface-list=$wanList src-address-list=!fsr_trusted6 log=yes log-prefix="FSR-HONEY6" comment="FSR: honeyports6" place-before=$fa6
  :put "FSR: [ok] IPv6"
} on-error={ :put "FSR: [ERROR] modulo IPv6"; :log error "FSR: fallo modulo IPv6" }
}


# ============================ Hardening ======================================
# Basado en "Securing your router". No se revierte con fsr-uninstall: ver fsr-pre-install.rsc
:if ($modHardening) do={
  :if ($hMacServer) do={
    :do { /tool mac-server set allowed-interface-list=none } on-error={ :put "FSR: aviso mac-server" }
    :do { /tool mac-server mac-winbox set allowed-interface-list=$lanList } on-error={ :put "FSR: aviso mac-winbox" }
    :do { /tool mac-server ping set enabled=no } on-error={ :put "FSR: aviso mac-ping" }
  }
  :if ($hNeighbor) do={ :do { /ip neighbor discovery-settings set discover-interface-list=$lanList } on-error={ :put "FSR: aviso neighbor discovery" } }
  :if ($hBtest) do={ :do { /tool bandwidth-server set enabled=no } on-error={ :put "FSR: aviso bandwidth-server" } }
  :if ($hProxy) do={ :do { /ip proxy set enabled=no } on-error={ :put "FSR: aviso proxy" } }
  :if ($hSocks) do={ :do { /ip socks set enabled=no } on-error={ :put "FSR: aviso socks" } }
  :if ($hUpnp) do={ :do { /ip upnp set enabled=no } on-error={ :put "FSR: aviso upnp" } }
  :if ($hSsh) do={ :do { /ip ssh set strong-crypto=yes } on-error={ :put "FSR: aviso ssh strong-crypto" } }
  :if ($hRomon) do={ :do { /tool romon set enabled=no } on-error={ :put "FSR: aviso romon" } }
  :if ($hServices) do={
    :foreach s in={"telnet";"ftp";"www";"api"} do={
      :do { /ip service set [find where name=$s] disabled=yes } on-error={ :put ("FSR: aviso service " . $s) }
    }
  }
  :if ($disableCloud) do={
    # >= 7.17 ddns-enabled solo admite yes|auto ("auto" = off si Back To Home no esta activo).
    # Valor en variable: se valida en ejecucion y lo captura on-error (literal = syntax error al parsear)
    :local dd "no"
    :if ($minor >= 17) do={ :set dd "auto" }
    :do { /ip cloud set ddns-enabled=$dd update-time=no } on-error={ :put "FSR: aviso ip cloud (desactiva antes Back To Home si esta en uso)" }
  }
  :if ($restrictServices) do={
    :do { /ip service set [find where !disabled] address=$mgmtNets } on-error={ :put "FSR: aviso restrict services" }
    :put ("FSR: servicios restringidos a " . $mgmtNets)
  }
  :put "FSR: [ok] Hardening"
}


# ============================ Logging remoto =================================
:if ([:len $logRemote] > 0) do={
:do {
  /system logging action add name=fsr-remote target=remote remote=$logRemote remote-port=$logRemotePort
  /system logging add topics=firewall action=fsr-remote
  :put ("FSR: [ok] logs firewall -> " . $logRemote . ":" . $logRemotePort)
} on-error={ :put "FSR: [ERROR] logging remoto" }
}


# ============================ Resumen ========================================
:put ("FSR: filter=" . [:len [/ip firewall filter find where comment~"^FSR:"]] . " raw=" . [:len [/ip firewall raw find where comment~"^FSR:"]] . " filter6=" . [:len [/ipv6 firewall filter find where comment~"^FSR:"]] . " raw6=" . [:len [/ipv6 firewall raw find where comment~"^FSR:"]])
:log info "FSR: instalacion completada"
:if ($rollback > 0s) do={ :put "FSR: comprueba el acceso y confirma con  :global fsrConfirmed true" }
}
