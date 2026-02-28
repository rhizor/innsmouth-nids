#!/usr/bin/env python3
"""
Innsmouth NIDS - PCAP Analyzer
Analiza archivos PCAP para detectar amenazas.
"""

import sys
import json
import argparse
from pathlib import Path
from collections import defaultdict
from datetime import datetime

try:
    from scapy.all import rdpcap, TCP, UDP, IP, ICMP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: scapy not installed. Install with: pip install scapy")


class InnsmouthAnalyzer:
    """Analizador de tráfico de red para Innsmouth NIDS."""
    
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.packets = []
        self.stats = defaultdict(int)
        self.findings = []
        self.credentials_found = []
        self.scan_indicators = []
    
    def load_pcap(self):
        """Cargar archivo PCAP."""
        if not SCAPY_AVAILABLE:
            print("Error: scapy is required for PCAP analysis")
            print("Install with: pip install scapy")
            sys.exit(1)
        
        print(f"[*] Loading PCAP: {self.pcap_file}")
        self.packets = rdpcap(self.pcap_file)
        print(f"[+] Loaded {len(self.packets)} packets")
    
    def analyze(self):
        """Ejecutar análisis completo."""
        print("\n[*] Starting analysis...")
        
        self._analyze_protocols()
        self._detect_plaintext_credentials()
        self._detect_port_scans()
        self._analyze_traffic_patterns()
        
        print("[+] Analysis complete\n")
    
    def _analyze_protocols(self):
        """Analizar distribución de protocolos."""
        for pkt in self.packets:
            if IP in pkt:
                self.stats['total_packets'] += 1
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                
                if TCP in pkt:
                    self.stats['tcp_packets'] += 1
                    self.stats[f"port_{pkt[TCP].dport}"] += 1
                elif UDP in pkt:
                    self.stats['udp_packets'] += 1
                elif ICMP in pkt:
                    self.stats['icmp_packets'] += 1
    
    def _detect_plaintext_credentials(self):
        """Detectar credenciales en texto plano."""
        print("[*] Checking for plaintext credentials...")
        
        cred_patterns = [
            (b"username=", "HTTP Username"),
            (b"password=", "HTTP Password"),
            (b"Authorization: Basic", "Basic Auth"),
            (b"USER ", "FTP USER"),
            (b"PASS ", "FTP PASS"),
            (b"AUTH LOGIN", "SMTP AUTH"),
            (b"login=", "Login Parameter"),
            (b"api_key=", "API Key"),
            (b"token=", "Token"),
        ]
        
        for pkt in self.packets:
            if Raw in pkt:
                payload = pkt[Raw].load
                for pattern, cred_type in cred_patterns:
                    if pattern.lower() in payload.lower():
                        self.credentials_found.append({
                            'type': cred_type,
                            'src': pkt[IP].src if IP in pkt else 'Unknown',
                            'dst': pkt[IP].dst if IP in pkt else 'Unknown',
                            'packet_num': pkt.number
                        })
    
    def _detect_port_scans(self):
        """Detectar indicadores de escaneo de puertos."""
        port_access = defaultdict(set)
        
        for pkt in self.packets:
            if TCP in pkt and IP in pkt:
                src = pkt[IP].src
                dst = pkt[IP].dst
                dport = pkt[TCP].dport
                flags = pkt[TCP].flags
                
                # SYN scan indicator
                if flags == 'S':
                    port_access[src].add(f"{dst}:{dport}")
        
        # Detectar múltiples puertos accedidos desde misma IP
        for src, targets in port_access.items():
            if len(targets) > 10:
                self.scan_indicators.append({
                    'type': 'Port Scan',
                    'source': src,
                    'targets': len(targets),
                    'details': list(targets)[:20]
                })
    
    def _analyze_traffic_patterns(self):
        """Analizar patrones de tráfico."""
        # Analizar volumen por IP
        ip_traffic = defaultdict(lambda: {'sent': 0, 'recv': 0})
        
        for pkt in self.packets:
            if IP in pkt:
                ip = pkt[IP]
                size = len(pkt)
                ip_traffic[ip.src]['sent'] += size
                ip_traffic[ip.dst]['recv'] += size
        
        # IPs con alto volumen
        for ip, traffic in ip_traffic.items():
            total = traffic['sent'] + traffic['recv']
            if total > 1000000:  # > 1MB
                self.findings.append({
                    'type': 'High Traffic',
                    'ip': ip,
                    'volume': total,
                    'unit': 'bytes'
                })
    
    def generate_report(self, output_file=None):
        """Generar reporte de análisis."""
        report = {
            'timestamp': datetime.now().isoformat(),
            'pcap_file': self.pcap_file,
            'summary': {
                'total_packets': self.stats['total_packets'],
                'tcp_packets': self.stats['tcp_packets'],
                'udp_packets': self.stats['udp_packets'],
                'icmp_packets': self.stats['icmp_packets'],
            },
            'findings': self.findings,
            'credentials_found': self.credentials_found,
            'scan_indicators': self.scan_indicators,
            'top_ports': self._get_top_ports()
        }
        
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"[+] Report saved to: {output_file}")
        
        self._print_summary(report)
        return report
    
    def _get_top_ports(self):
        """Obtener puertos más accedidos."""
        ports = {k.replace('port_', ''): v 
                 for k, v in self.stats.items() 
                 if k.startswith('port_')}
        sorted_ports = sorted(ports.items(), key=lambda x: x[1], reverse=True)
        return dict(sorted_ports[:10])
    
    def _print_summary(self, report):
        """Imprimir resumen en consola."""
        print("=" * 60)
        print("INNSMOUTH NIDS - ANALYSIS REPORT")
        print("=" * 60)
        
        print(f"\n📊 Traffic Summary:")
        print(f"   Total Packets: {report['summary']['total_packets']}")
        print(f"   TCP: {report['summary']['tcp_packets']}")
        print(f"   UDP: {report['summary']['udp_packets']}")
        print(f"   ICMP: {report['summary']['icmp_packets']}")
        
        if self.credentials_found:
            print(f"\n🔴 Credentials Found: {len(self.credentials_found)}")
            for cred in self.credentials_found:
                print(f"   - {cred['type']} from {cred['src']} to {cred['dst']}")
        
        if self.scan_indicators:
            print(f"\n🟠 Port Scan Indicators: {len(self.scan_indicators)}")
            for scan in self.scan_indicators:
                print(f"   - {scan['type']} from {scan['source']} -> {scan['targets']} targets")
        
        if self.findings:
            print(f"\n🟡 Findings: {len(self.findings)}")
            for finding in self.findings:
                print(f"   - {finding['type']}: {finding.get('ip', 'N/A')}")
        
        print("\n📡 Top Ports:")
        for port, count in report['top_ports'].items():
            print(f"   Port {port}: {count} packets")
        
        print("\n" + "=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description='Innsmouth NIDS - PCAP Analyzer'
    )
    parser.add_argument('pcap', help='Path to PCAP file')
    parser.add_argument('-o', '--output', help='Output JSON file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    if not Path(args.pcap).exists():
        print(f"Error: File not found: {args.pcap}")
        sys.exit(1)
    
    analyzer = InnsmouthAnalyzer(args.pcap)
    analyzer.load_pcap()
    analyzer.analyze()
    analyzer.generate_report(args.output)


if __name__ == "__main__":
    main()
