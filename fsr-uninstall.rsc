# =============================================================================
#  fsr-uninstall.rsc - elimina todo lo creado por fsr.rsc
#  /import file-name=fsr-uninstall.rsc verbose=yes
#  Tambien lo invoca el rollback automatico si no se confirma la instalacion.
#  NO revierte el hardening de servicios: compara con fsr-pre-install.rsc
# =============================================================================
{
:global fsrConfirmed
:set fsrConfirmed true
/ip firewall filter remove [find where comment~"^FSR:"]
/ip firewall raw remove [find where comment~"^FSR:"]
/ip firewall address-list remove [find where list~"^fsr_"]
/ipv6 firewall filter remove [find where comment~"^FSR:"]
/ipv6 firewall raw remove [find where comment~"^FSR:"]
/ipv6 firewall address-list remove [find where list~"^fsr_"]
/system logging remove [find where action="fsr-remote"]
/system logging action remove [find where name="fsr-remote"]
/system script environment remove [find where name="fsrConfirmed"]
:log warning "FSR: desinstalado"
:put "FSR: desinstalado. El hardening de servicios no se revierte (ver fsr-pre-install.rsc)"
}
