# Innsmouth NIDS 🐟🔱

<p align="center">
  <img src="https://img.shields.io/badge/Security-Onion-2.6.0+-orange.svg" alt="Security Onion">
  <img src="https://img.shields.io/badge/Suricata-6.0+-red.svg" alt="Suricata">
  <img src="https://img.shields.io/badge/Zeek-4.0+-blue.svg" alt="Zeek">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
</p>

**Innsmouth NIDS** es un sistema de detección de intrusiones basado en red (NIDS) que utiliza Security Onion (Zeek + Suricata) para capturar tráfico y detectar amenazas como escaneos de puertos, credenciales en texto claro, y otras anomalías de red.

Este proyecto documenta la configuración, reglas personalizadas de detección, y análisis de tráfico para un laboratorio Blue Team.

> *"The thing cannot be described - there is no language for such abysms of shrieking malignancy..."* — H.P. Lovecraft, The Shadow over Innsmouth

## 📡 Arquitectura

```
┌─────────────────────────────────────────────────────────────────┐
│                        RED A MONITOREAR                         │
│                   (Puerto espejo / Tap port)                    │
└─────────────────────┬───────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│                    INNSMOUTH NIDS NODE                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐│
│  │   Zeek      │  │  Suricata   │  │   Security Onion       ││
│  │  (Analisis) │  │  (Detección)│  │   (Gestión/Alertas)    ││
│  │  - conn.log │  │  - Rules    │  │   - Dashboard          ││
│  │  - http.log │  │  - Eve.json │  │   - ElastAlert         ││
│  │  - dns.log  │  │             │  │   - Squert             ││
│  └─────────────┘  └─────────────┘  └─────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

## ⚠️ Requisitos

- **Hardware**: VM con mínimo 8GB RAM, 4 CPU cores, 500GB disco
- **Software**: Security Onion 2.6.0+ (Ubuntu 20.04/22.04)
- **Acceso**: Puerto espejo (mirror port) o TAP físico

## 🚀 Instalación

### 1. Instalar Security Onion

```bash
# Descargar ISO desde https://securityonion.net
# O usar Docker (para pruebas)

# Instalación mínima en Ubuntu:
sudo apt update
sudo apt install -y curl wget gnupg

# Agregar repositorio Security Onion
curl -fsSL https://download.securityonion.net/file/securityonion/SecurityOnion_2.6.0_amd64.iso -o securityonion.iso

# Montar e instalar
sudo mkdir -p /mnt/so
sudo mount -o loop securityonion.iso /mnt/so
sudo /mnt/so/sosetup
```

### 2. Configurar Puerto Espejo

#### En switches Cisco:
```cisco
! Configurar puerto espejo (SPAN)
monitor session 1 source interface Gi1/0/1 - 24
monitor session 1 destination interface Gi1/0/48
```

#### En switches HP/Aruba:
```hp
# Puerto espejo en HP ProCurve
mirror-port 48
interface 1-24
    monitor
```

#### En Linux (ifstats/TAP virtual):
```bash
# Crear interfaz TAP
ip link add tap0 type tap
ip link set tap0 up

# Crear bridge para monitorear tráfico
brctl addbr br0
brctl addif br0 eth0
brctl addif br0 tap0

# O usar tcpdump para testing
sudo tcpdump -i eth0 -w capture.pcap
```

### 3. Configuración de Zeek

```bash
# Personalizar configuración de Zeek
sudo vim /opt/zeek/etc/node.cfg

# Habilitar logs específicos
sudo vim /opt/zeek/share/zeek/site/local.zeek

# Reiniciar Zeek
sudo so-zeek-restart
```

### 4. Configuración de Suricata

```bash
# Ubicación de reglas
ls -la /opt/securityonion/suricata/etc/suricata/

# Agregar reglas custom
sudo cp innsmouth.rules /opt/securityonion/suricata/rules/
sudo so-suricata-restart
```

## 📝 Reglas de Detección

Las reglas personalizadas están en el directorio `rules/`.

### Reglas Incluidas:

| Archivo | Descripción |
|---------|-------------|
| `rules/port_scan.rules` | Detección de escaneos de puertos |
| `rules/plaintext_creds.rules` | Credenciales en HTTP/FTP/Telnet |
| `rules/anomaly_detection.rules` | Anomalías de tráfico |
| `rules/exfiltration.rules` | Posible exfiltración de datos |
| `rules/malware_traffic.rules` | Tráfico relacionado con malware |

### Ejemplo de Regla Suricata:

```yaml
# rules/plaintext_creds.rules

# Detectar username/password en HTTP POST
alert http any any -> any any (msg:"INNSMOUTH HTTP Plaintext Credentials Detected"; \
  content:"username="; nocase; content:"password="; nocase; \
  classtype:attempted-admin; sid:1000001; rev:1;)

# Detectar Basic Auth en texto plano
alert http any any -> any any (msg:"INNSMOUTH HTTP Basic Auth Detected"; \
  http.header; content:"Authorization|3A| Basic"; nocase; \
  classtype:attempted-admin; sid:1000002; rev:1;)

# Detectar credenciales en FTP
alert tcp any any -> any 21 (msg:"INNSMOUTH FTP Credentials Detected"; \
  content:"USER"; nocase; content:"PASS"; nocase; \
  classtype:attempted-admin; sid:1000003; rev:1;)
```

## 🔍 Análisis de Tráfico

### Scripts de Análisis Inclidos:

```bash
# Analizar captura PCAP
python3 scripts/analyze_pcap.py captura.pcap

# Detectar escaneos en logs Zeek
python3 scripts/detect_scans.py /nsm/zeek/logs/

# Analizar tráfico HTTP
python3 scripts/analyze_http.py /nsm/zeek/logs/http.log

# Generar reporte de alertas
python3 scripts/alert_report.py --period 24h
```

### Queries Útiles para Zeek:

```bash
# Ver conexiones
zq -f table "id.orig_h, id.resp_h, id.resp_p, proto, conn_state" *.conn.log

# Analizar tráfico HTTP
zq -f table "id.orig_h, id.resp_h, uri, user_agent" *.http.log | head -20

# DNS queries sospechosas
zq -f table "id.orig_h, query, qtype" *.dns.log | grep -E "evil|test|malware"

# Detectar escaneos (many failed connections)
zq -f table "id.orig_h, id.resp_p, conn_state" *.conn.log | grep S0 | sort | uniq -c | sort -rn
```

## 📊 Dashboard

Acceder a Security Onion Dashboard:

```
https://localhost
Username: admin
Password: (configurado durante instalación)
```

### Kibana Dashboards Incluidos:
- Network Traffic Overview
- Threat Detection Dashboard
- IOC Hunt Dashboard
- Compliance Status

## 🧪 Pruebas

### Generar Tráfico de Prueba

```bash
# Escaneo de puertos con nmap
nmap -sS -p 1-1000 192.168.1.100

# Simular tráfico HTTP con credenciales
curl -u admin:password http://192.168.1.100/

# Generar tráfico FTP
ftp 192.168.1.100

# Test de reglas Suricata
sudo suricata -r captura.pcap -c /etc/suricata/suricata.yaml -k all -v
```

### Ejecutar Tests

```bash
# Tests del proyecto
python3 -m pytest tests/ -v

# Validar reglas Suricata
suricata -T -c /etc/suricata/suricata.yaml -r /dev/null
```

## 📁 Estructura del Proyecto

```
innsmouth-nids/
├── README.md
├── docs/
│   ├── SETUP.md
│   ├── ARCHITECTURE.md
│   └── TROUBLESHOOTING.md
├── rules/
│   ├── port_scan.rules
│   ├── plaintext_creds.rules
│   ├── anomaly_detection.rules
│   ├── exfiltration.rules
│   └── malware_traffic.rules
├── scripts/
│   ├── analyze_pcap.py
│   ├── detect_scans.py
│   ├── analyze_http.py
│   └── alert_report.py
├── configs/
│   ├── zeek_custom.yaml
│   └── suricata_custom.yaml
├── tests/
│   ├── test_rules.py
│   └── test_analysis.py
└── docs/
    └── README.md
```

## 🔐 Variables de Entorno

| Variable | Descripción |
|----------|-------------|
| `INNSMOUTH_LOG_PATH` | Ruta de logs de Zeek |
| `INNSMOUTH_ALERT_THRESHOLD` | Umbral de alertas |
| `INNSMOUTH_NETWORK_CIDR` | Red a monitorear |
| `SO_USERNAME` | Usuario de Security Onion |
| `SO_PASSWORD` | Password de Security Onion |

## 📖 Documentación Adicional

- [Setup Detallado](docs/SETUP.md)
- [Arquitectura del Sistema](docs/ARCHITECTURE.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)

## 🤝 Contribuir

1. Fork el proyecto
2. Crear branch (`git checkout -b feature/nueva-regla`)
3. Commitear cambios (`git commit -am 'Agregar nueva regla'`)
4. Pushear (`git push origin feature/nueva-regla`)
5. Crear Pull Request

## 📜 Licencia

MIT License - ver LICENSE para detalles.

---

*"That is not dead which can eternal lie, and with strange aeons even death may die."* — H.P. Lovecraft, The Nameless City
