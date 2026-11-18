#!/usr/bin/env bash
# Uso: ./knock.sh <host> <p1> <p2> <p3>     ej: ./knock.sh vpn.ejemplo.es 48211 9337 29004
# Envia un SYN a cada puerto en orden (el router lo descarta: el timeout es lo esperado).
set -u
[ $# -lt 2 ] && { echo "uso: $0 host p1 [p2 ...]"; exit 1; }
host=$1; shift
for p in "$@"; do
  timeout 1 bash -c "echo > /dev/tcp/$host/$p" 2>/dev/null
  echo "knock $host:$p"
  sleep 0.5
done
echo "hecho: tienes la ventana configurada en knockTime"
