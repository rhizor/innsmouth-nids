# Innsmouth NIDS - Setup Guide

## Requisitos del Sistema

### Hardware Mínimo
- **CPU**: 4 cores (8+ recomendado)
- **RAM**: 8 GB (16 GB recomendado)
- **Dis GB SSDco**: 500 (1 TB recomendado)
- **Red**: 2 interfaces de red (1 para management, 1 para monitoreo)

### Software Requerido
- Ubuntu Server 20.04 LTS o 22.04 LTS
- Security Onion 2.6.0+
- Python 3.8+

## Instalación Paso a Paso

### 1. Preparar la VM

```bash
# Actualizar sistema
sudo apt update && sudo apt upgrade -y

# Instalar dependencias
sudo apt install -y curl wget gnupg2 software-properties-common

# Configurar red
sudo vim /etc/netplan/01-netcfg.yaml
```

Configuración de red ejemplo:
```yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    ens160:
      dhcp4: no
      addresses: [192.168.1.10/24]
      gateway4: 192.168.1.1
      nameservers:
        addresses: [8.8.8.8,8.8.4.4]
    ens192:
      dhcp4: no
```

### 2. Descargar Security Onion

```bash
# Método 1: Descargar ISO
wget https://download.securityonion.net/file/securityonion/SecurityOnion_2.6.0_64.iso

# Método 2: Agregar repositorio e instalar (Ubuntu)
curl -fsSL https://download.securityonion.net/file/securityonion/SecurityOnion_2.6.0_amd64.deb -o securityonion.deb
sudo dpkg -i securityonion.deb
sudo apt-get install -f
```

### 3. Ejecutar Setup

```bash
# Iniciar configuración
sudo sosetup

# O usando modo no-interactivo (advanced)
sudo sosetup --auto
```

Durante el setup:
- Elegir "Evaluation Mode" para laboratorio
- Configurar interfaz de monitoreo (ej: ens192)
- Configurar usuario admin
- Habilitar servicios: Zeek, Suricata, Wazuh, Kibana

### 4. Configurar Puerto Espejo (SPAN)

#### Switch Cisco:
```cisco
! En modo configuración
enable
configure terminal

! Crear VLAN de.management
vlan 100
 name INNSMOUTH-MON

! Configurar SPAN
monitor session 1 source vlan 100
monitor session 1 destination interface Gi1/0/48
monitor session 1 mode active

! Verificar
show monitor session 1
```

#### Switch HP/Aruba:
```hp
# Configurar puerto espejo
mirror-port 48

# Agregar puertos a monitorear
vlan 100
   tagged 48
   monitor
```

#### Switch Linux (OVS):
```bash
# Crear bridge con puerto mirror
ovs-vsctl add-br br0
ovs-vsctl add-port br0 eth0
ovs-vsctl add-port br0 tap0 -- set Interface tap0 type=internal

# Habilitar mirroring
ovs-vsctl set port eth0 mirror=@m -- \
  --id=@m create mirror name=innsmouth-mirror \
  select-src-port=eth0 select-dst-port=eth0 output-port=tap0
```

### 5. Verificar Captura de Tráfico

```bash
# Ver tráfico en interfaz de monitoreo
sudo tcpdump -i ens192 -c 10

# Ver estadísticas de red
sudo ifconfig ens192

# Ver logs de Zeek
ls -la /nsm/zeek/logs/

# Ver alertas de Suricata
tail -f /nsm/suricata/logs/eve.json | jq
```

## Configuración Post-Instalación

### Habilitar Reglas Custom

```bash
# Copiar reglas
sudo cp innsmouth-nids/rules/*.rules /opt/securityonion/suricata/rules/

# Actualizar sid-msg.map
sudo cat /opt/securityonion/suricata/rules/*.rules | grep -oP 'sid:\K[0-9]+' | \
  while read sid; do
    echo "$sid INNSMOUTH custom rule" >> /opt/securityonion/suricatorules/sid-msg.map
  done

# Reiniciar Suricata
sudo so-suricata-restart
```

### Configurar Alertas Email

```bash
# Configurar ElastAlert
sudo vim /etc/elastalert/rules/innsmouth_alerts.yaml

# Reiniciar servicio
sudo systemctl restart elastalert
```

## Verificación del Sistema

### Checklist de Verificación

- [ ] Security Onion instalado correctamente
- [ ] Interfaz de monitoreo recibe tráfico
- [ ] Zeek generando logs
- [ ] Suricata cargando reglas
- [ ] Dashboard accesible
- [ ] Alertas funcionando

### Comandos de Verificación

```bash
# Estado de servicios
sudo so-status

# Verificación de Zeek
sudo so-zeek-status

# Verificación de Suricata
sudo so-suricata-status

# Verificación de Wazuh
sudo so-wazuh-status
```

## Troubleshooting

### Sin Tráfico en Interfaz

```bash
# Verificar configuración de switch
show monitor

# Probar con tráfico generado
sudo hping3 -c 100 -i 1 192.168.1.1

# Ver con tcpdump
sudo tcpdump -i ens192 -nn
```

### Zeek No Genera Logs

```bash
# Ver estado del servicio
sudo systemctl status zeek

# Revisar configuración
sudo /opt/zeek/bin/zeekctl status

# Ver logs de errores
sudo tail -f /opt/zeek/logs/zeek.stderr
```

### Suricata No Inicia

```bash
# Validar configuración
sudo suricata -T -c /opt/securityonion/suricata/etc/suricata.yaml

# Ver errores
sudo tail -f /nsm/suricata/logs/suricata.log
```
