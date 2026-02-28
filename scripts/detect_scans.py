#!/usr/bin/env python3
"""
Innsmouth NIDS - Port Scan Detector
Analiza logs de Zeek para detectar escaneos de puertos.
"""

import os
import json
import argparse
from pathlib import Path
from collections import defaultdict
from datetime import datetime, timedelta


class PortScanDetector:
    """Detector de escaneos de puertos usando logs de Zeek."""
    
    def __init__(self, log_dir):
        self.log_dir = log_dir
        self.connections = []
        self.scan_results = []
    
    def load_conn_logs(self):
        """Cargar logs de conexión de Zeek."""
        conn_log = os.path.join(self.log_dir, 'conn.log')
        
        if not os.path.exists(conn_log):
            # Buscar archivos con patrón
            for f in os.listdir(self.log_dir):
                if f.startswith('conn.log'):
                    conn_log = os.path.join(self.log_dir, f)
                    break
        
        if not os.path.exists(conn_log):
            print(f"Error: No se encontró conn.log en {self.log_dir}")
            return
        
        print(f"[*] Loading connections from: {conn_log}")
        
        with open(conn_log, 'r') as f:
            for line in f:
                if line.strip() and not line.startswith('#'):
                    try:
                        # Zeek JSON format
                        self.connections.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        
        print(f"[+] Loaded {len(self.connections)} connections")
    
    def detect_syn_scans(self):
        """Detectar escaneos SYN."""
        print("[*] Detecting SYN scans...")
        
        syn_attempts = defaultdict(list)
        
        for conn in self.connections:
            # Conexiones sin respuesta (S0 state)
            if conn.get('conn_state') == 'S0':
                src = conn.get('id.orig_h', 'unknown')
                dst = conn.get('id.resp_h', 'unknown')
                dport = conn.get('id.resp_p', 0)
                ts = conn.get('ts', 0)
                
                syn_attempts[src].append({
                    'target': dst,
                    'port': dport,
                    'timestamp': ts
                })
        
        # Analizar IPs con muchos intentos SYN
        for src, attempts in syn_attempts.items():
            if len(attempts) >= 10:  # Threshold
                unique_targets = set(a['target'] for a in attempts)
                unique_ports = set(a['port'] for a in attempts)
                
                self.scan_results.append({
                    'type': 'SYN Scan',
                    'source': src,
                    'attempts': len(attempts),
                    'unique_targets': len(unique_targets),
                    'unique_ports': len(unique_ports),
                    'severity': 'HIGH' if len(attempts) > 50 else 'MEDIUM'
                })
        
        return self.scan_results
    
    def detect_port_probing(self):
        """Detectar probing de puertos específicos."""
        print("[*] Detecting port probing...")
        
        port_access = defaultdict(lambda: defaultdict(int))
        
        for conn in self.connections:
            src = conn.get('id.orig_h', 'unknown')
            dport = conn.get('id.resp_p', 0)
            
            if dport > 0:
                port_access[src][dport] += 1
        
        # IPs accediendo muchos puertos diferentes
        for src, ports in port_access.items():
            if len(ports) >= 20:
                self.scan_results.append({
                    'type': 'Port Probing',
                    'source': src,
                    'unique_ports': len(ports),
                    'ports': list(ports.keys())[:30],
                    'severity': 'MEDIUM'
                })
    
    def detect_service_scans(self):
        """Detectar escaneos de servicios específicos."""
        print("[*] Detecting service scans...")
        
        service_ports = {
            22: 'SSH',
            23: 'Telnet',
            80: 'HTTP',
            443: 'HTTPS',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            5900: 'VNC',
            8080: 'HTTP-Alt'
        }
        
        service_scans = defaultdict(list)
        
        for conn in self.connections:
            src = conn.get('id.orig_h', 'unknown')
            dport = conn.get('id.resp_p', 0)
            
            if dport in service_ports:
                service_scans[src].append({
                    'port': dport,
                    'service': service_ports[dport]
                })
        
        for src, services in service_scans.items():
            unique_services = set(s['service'] for s in services)
            
            if len(unique_services) >= 3:
                self.scan_results.append({
                    'type': 'Service Scan',
                    'source': src,
                    'services': list(unique_services),
                    'severity': 'LOW'
                })
    
    def analyze(self):
        """Ejecutar análisis completo."""
        self.load_conn_logs()
        
        if not self.connections:
            print("No connections to analyze")
            return
        
        self.detect_syn_scans()
        self.detect_port_probing()
        self.detect_service_scans()
        
        return self.scan_results
    
    def generate_report(self, output_file=None):
        """Generar reporte."""
        report = {
            'timestamp': datetime.now().isoformat(),
            'log_directory': self.log_dir,
            'total_connections': len(self.connections),
            'scans_detected': len(self.scan_results),
            'findings': self.scan_results
        }
        
        # Imprimir reporte
        print("\n" + "=" * 60)
        print("INNSMOUTH NIDS - PORT SCAN DETECTION REPORT")
        print("=" * 60)
        
        print(f"\n📊 Summary:")
        print(f"   Total Connections: {report['total_connections']}")
        print(f"   Scans Detected: {report['scans_detected']}")
        
        if self.scan_results:
            print(f"\n🔴 Findings:")
            
            high_sev = [s for s in self.scan_results if s.get('severity') == 'HIGH']
            med_sev = [s for s in self.scan_results if s.get('severity') == 'MEDIUM']
            low_sev = [s for s in self.scan_results if s.get('severity') == 'LOW']
            
            print(f"   HIGH: {len(high_sev)}")
            print(f"   MEDIUM: {len(med_sev)}")
            print(f"   LOW: {len(low_sev)}")
            
            for scan in self.scan_results:
                severity_icon = "🔴" if scan.get('severity') == 'HIGH' else "🟠" if scan.get('severity') == 'MEDIUM' else "🟡"
                print(f"\n   {severity_icon} {scan['type']} from {scan['source']}")
                print(f"      Severity: {scan.get('severity')}")
                
                if 'attempts' in scan:
                    print(f"      Attempts: {scan['attempts']}")
                if 'unique_targets' in scan:
                    print(f"      Unique Targets: {scan['unique_targets']}")
                if 'unique_ports' in scan:
                    print(f"      Unique Ports: {scan['unique_ports']}")
        else:
            print("\n✅ No scans detected")
        
        print("\n" + "=" * 60)
        
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"\n[+] Report saved to: {output_file}")
        
        return report


def main():
    parser = argparse.ArgumentParser(
        description='Innsmouth NIDS - Port Scan Detector'
    )
    parser.add_argument('log_dir', help='Directory containing Zeek conn.log')
    parser.add_argument('-o', '--output', help='Output JSON file')
    parser.add_argument('-t', '--threshold', type=int, default=10, 
                       help='Minimum connections to flag as scan')
    
    args = parser.parse_args()
    
    if not Path(args.log_dir).exists():
        print(f"Error: Directory not found: {args.log_dir}")
        sys.exit(1)
    
    detector = PortScanDetector(args.log_dir)
    detector.analyze()
    detector.generate_report(args.output)


if __name__ == "__main__":
    import sys
    main()
