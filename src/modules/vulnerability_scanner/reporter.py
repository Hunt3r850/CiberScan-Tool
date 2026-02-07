"""
Clase VulnerabilityReporter para generar informes de vulnerabilidades.

Esta clase proporciona métodos para crear informes detallados
sobre las vulnerabilidades encontradas durante los escaneos.
"""

import os
import json
import logging
import datetime
import matplotlib.pyplot as plt
import numpy as np

class VulnerabilityReporter:
    def __init__(self, output_dir="./reports", log_level=logging.INFO):
        """
        Inicializa un nuevo objeto VulnerabilityReporter.
        
        Args:
            output_dir (str, opcional): Directorio para guardar los informes
            log_level (int, opcional): Nivel de logging
        """
        self.output_dir = output_dir
        self.logger = self._setup_logger(log_level)
        
        # Crear directorio de salida si no existe
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
    def _setup_logger(self, log_level):
        """
        Configura el logger para el generador de informes.
        
        Args:
            log_level (int): Nivel de logging
            
        Returns:
            Logger: Objeto logger configurado
        """
        logger = logging.getLogger("VulnerabilityReporter")
        logger.setLevel(log_level)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            
        return logger
        
    def generate_text_report(self, scan_results, hosts_info=None, output_file=None):
        """
        Genera un informe de texto sobre las vulnerabilidades encontradas.
        
        Args:
            scan_results (dict): Resultados del escaneo por host
            hosts_info (dict, opcional): Información adicional sobre los hosts
            output_file (str, opcional): Ruta del archivo de salida
            
        Returns:
            str: Ruta del archivo generado o contenido del informe si no se especifica archivo
        """
        self.logger.info("Generando informe de texto")
        
        # Preparar nombre de archivo si no se especifica
        if output_file is None:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = os.path.join(self.output_dir, f"vulnerability_report_{timestamp}.txt")
            
        # Iniciar informe
        report = []
        report.append("=" * 80)
        report.append("INFORME DE ANÁLISIS DE VULNERABILIDADES")
        report.append("=" * 80)
        report.append(f"Fecha: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Hosts analizados: {len(scan_results)}")
        report.append("")
        
        # Resumen de vulnerabilidades
        total_vulns = sum(len(vulns) for vulns in scan_results.values())
        report.append(f"Total de vulnerabilidades encontradas: {total_vulns}")
        
        # Contar vulnerabilidades por severidad
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Unknown": 0}
        for host_vulns in scan_results.values():
            for vuln in host_vulns:
                severity = vuln.severity if hasattr(vuln, 'severity') else "Unknown"
                if severity in severity_counts:
                    severity_counts[severity] += 1
                else:
                    severity_counts["Unknown"] += 1
        
        report.append("\nDistribución por severidad:")
        for severity, count in severity_counts.items():
            report.append(f"- {severity}: {count}")
        
        report.append("\n" + "=" * 80)
        report.append("DETALLES POR HOST")
        report.append("=" * 80)
        
        # Detalles por host
        for ip, vulnerabilities in scan_results.items():
            report.append(f"\nHost: {ip}")
            
            # Añadir información adicional del host si está disponible
            if hosts_info and ip in hosts_info:
                host = hosts_info[ip]
                if hasattr(host, 'hostname') and host.hostname:
                    report.append(f"Hostname: {host.hostname}")
                if hasattr(host, 'os_info') and host.os_info:
                    os_name = host.os_info.get('name', 'Unknown')
                    report.append(f"Sistema Operativo: {os_name}")
                
                # Listar puertos abiertos
                if hasattr(host, 'ports'):
                    open_ports = [p for p in host.ports if p.state == 'open']
                    if open_ports:
                        port_list = ", ".join([f"{p.number}/{p.protocol}" for p in open_ports[:10]])
                        if len(open_ports) > 10:
                            port_list += f" y {len(open_ports) - 10} más"
                        report.append(f"Puertos abiertos: {port_list}")
            
            # Listar vulnerabilidades
            report.append(f"\nVulnerabilidades encontradas: {len(vulnerabilities)}")
            
            # Ordenar por severidad (Critical primero)
            severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Unknown": 4}
            sorted_vulns = sorted(
                vulnerabilities,
                key=lambda v: severity_order.get(v.severity if hasattr(v, 'severity') else "Unknown", 5)
            )
            
            for i, vuln in enumerate(sorted_vulns, 1):
                report.append(f"\n{i}. {vuln.vuln_id} - {vuln.name}")
                report.append(f"   Severidad: {vuln.severity}")
                if vuln.cvss_score is not None:
                    report.append(f"   CVSS: {vuln.cvss_score}")
                if vuln.description:
                    desc_lines = vuln.description.split('\n')
                    for line in desc_lines[:3]:  # Limitar a 3 líneas
                        report.append(f"   {line}")
                    if len(desc_lines) > 3:
                        report.append("   ...")
                
                # Sistemas afectados específicos
                if hasattr(vuln, 'affected_systems') and vuln.affected_systems:
                    for system in vuln.affected_systems[:3]:  # Limitar a 3 sistemas
                        service_info = system.get('service', '')
                        port_info = f":{system.get('port')}" if system.get('port') else ''
                        report.append(f"   Afecta a: {service_info}{port_info}")
                    if len(vuln.affected_systems) > 3:
                        report.append(f"   Y {len(vuln.affected_systems) - 3} servicios más")
                
                # Mitigación
                if vuln.mitigation:
                    report.append(f"   Mitigación: {vuln.mitigation[:100]}...")
                
                # Referencias
                if hasattr(vuln, 'references') and vuln.references:
                    report.append(f"   Referencias: {len(vuln.references)} disponibles")
        
        report.append("\n" + "=" * 80)
        report.append("RECOMENDACIONES")
        report.append("=" * 80)
        
        # Añadir recomendaciones generales
        report.append("\n1. Priorizar la mitigación de vulnerabilidades críticas y altas.")
        report.append("2. Actualizar el software y sistemas operativos a las últimas versiones.")
        report.append("3. Implementar un programa regular de parcheo de seguridad.")
        report.append("4. Revisar y fortalecer las configuraciones de seguridad.")
        report.append("5. Realizar escaneos de vulnerabilidades periódicos.")
        
        # Guardar informe
        report_content = "\n".join(report)
        
        with open(output_file, 'w') as f:
            f.write(report_content)
            
        self.logger.info(f"Informe de texto guardado en {output_file}")
        return output_file
        
    def generate_html_report(self, scan_results, hosts_info=None, output_file=None):
        """
        Genera un informe HTML sobre las vulnerabilidades encontradas.
        
        Args:
            scan_results (dict): Resultados del escaneo por host
            hosts_info (dict, opcional): Información adicional sobre los hosts
            output_file (str, opcional): Ruta del archivo de salida
            
        Returns:
            str: Ruta del archivo generado
        """
        self.logger.info("Generando informe HTML")
        
        # Preparar nombre de archivo si no se especifica
        if output_file is None:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = os.path.join(self.output_dir, f"vulnerability_report_{timestamp}.html")
            
        # Generar gráficos para el informe
        charts_dir = os.path.join(os.path.dirname(output_file), "charts")
        if not os.path.exists(charts_dir):
            os.makedirs(charts_dir)
            
        severity_chart = self._generate_severity_chart(scan_results, charts_dir)
        host_vulns_chart = self._generate_host_vulnerabilities_chart(scan_results, charts_dir)
        
        # Iniciar HTML
        html = []
        html.append("<!DOCTYPE html>")
        html.append("<html lang='es'>")
        html.append("<head>")
        html.append("    <meta charset='UTF-8'>")
        html.append("    <meta name='viewport' content='width=device-width, initial-scale=1.0'>")
        html.append("    <title>Informe de Vulnerabilidades</title>")
        html.append("    <style>")
        html.append("        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; color: #333; }")
        html.append("        h1, h2, h3 { color: #2c3e50; }")
        html.append("        .container { max-width: 1200px; margin: 0 auto; }")
        html.append("        .header { background-color: #34495e; color: white; padding: 20px; margin-bottom: 20px; }")
        html.append("        .summary { display: flex; justify-content: space-around; margin-bottom: 30px; }")
        html.append("        .summary-box { border: 1px solid #ddd; padding: 15px; border-radius: 5px; width: 30%; text-align: center; }")
        html.append("        .critical { background-color: #ff5252; color: white; }")
        html.append("        .high { background-color: #ff9800; color: white; }")
        html.append("        .medium { background-color: #ffeb3b; color: black; }")
        html.append("        .low { background-color: #4caf50; color: white; }")
        html.append("        .unknown { background-color: #9e9e9e; color: white; }")
        html.append("        .charts { display: flex; justify-content: space-around; margin-bottom: 30px; }")
        html.append("        .chart { width: 48%; }")
        html.append("        .host { background-color: #f9f9f9; padding: 15px; margin-bottom: 20px; border-radius: 5px; }")
        html.append("        .vulnerability { border-left: 4px solid #ddd; padding: 10px; margin: 10px 0; }")
        html.append("        .vulnerability.critical { border-left-color: #ff5252; }")
        html.append("        .vulnerability.high { border-left-color: #ff9800; }")
        html.append("        .vulnerability.medium { border-left-color: #ffeb3b; }")
        html.append("        .vulnerability.low { border-left-color: #4caf50; }")
        html.append("        .vulnerability.unknown { border-left-color: #9e9e9e; }")
        html.append("        table { width: 100%; border-collapse: collapse; }")
        html.append("        th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }")
        html.append("        th { background-color: #f2f2f2; }")
        html.append("    </style>")
        html.append("</head>")
        html.append("<body>")
        html.append("    <div class='container'>")
        html.append("        <div class='header'>")
        html.append("            <h1>Informe de Análisis de Vulnerabilidades</h1>")
        html.append(f"            <p>Fecha: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>")
        html.append(f"            <p>Hosts analizados: {len(scan_results)}</p>")
        html.append("        </div>")
        
        # Resumen de vulnerabilidades
        total_vulns = sum(len(vulns) for vulns in scan_results.values())
        
        # Contar vulnerabilidades por severidad
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Unknown": 0}
        for host_vulns in scan_results.values():
            for vuln in host_vulns:
                severity = vuln.severity if hasattr(vuln, 'severity') else "Unknown"
                if severity in severity_counts:
                    severity_counts[severity] += 1
                else:
                    severity_counts["Unknown"] += 1
        
        html.append("        <h2>Resumen</h2>")
        html.append("        <div class='summary'>")
        html.append(f"            <div class='summary-box'><h3>Total</h3><p>{total_vulns}</p></div>")
        html.append(f"            <div class='summary-box critical'><h3>Críticas</h3><p>{severity_counts['Critical']}</p></div>")
        html.append(f"            <div class='summary-box high'><h3>Altas</h3><p>{severity_counts['High']}</p></div>")
        html.append("        </div>")
        
        # Gráficos
        html.append("        <h2>Análisis</h2>")
        html.append("        <div class='charts'>")
        if severity_chart:
            rel_path = os.path.relpath(severity_chart, os.path.dirname(output_file))
            html.append(f"            <div class='chart'><img src='{rel_path}' alt='Distribución por severidad' width='100%'></div>")
        if host_vulns_chart:
            rel_path = os.path.relpath(host_vulns_chart, os.path.dirname(output_file))
            html.append(f"            <div class='chart'><img src='{rel_path}' alt='Vulnerabilidades por host' width='100%'></div>")
        html.append("        </div>")
        
        # Tabla de vulnerabilidades críticas y altas
        html.append("        <h2>Vulnerabilidades Críticas y Altas</h2>")
        html.append("        <table>")
        html.append("            <tr>")
        html.append("                <th>ID</th>")
        html.append("                <th>Nombre</th>")
        html.append("                <th>Severidad</th>")
        html.append("                <th>CVSS</th>")
        html.append("                <th>Host</th>")
        html.append("            </tr>")
        
        # Recopilar vulnerabilidades críticas y altas
        critical_high_vulns = []
        for ip, vulns in scan_results.items():
            for vuln in vulns:
                if vuln.severity in ["Critical", "High"]:
                    critical_high_vulns.append((ip, vuln))
        
        # Ordenar por severidad y CVSS
        critical_high_vulns.sort(key=lambda x: (0 if x[1].severity == "Critical" else 1, 
                                              -(x[1].cvss_score or 0)))
        
        # Añadir filas a la tabla
        for ip, vuln in critical_high_vulns:
            severity_class = vuln.severity.lower() if hasattr(vuln, 'severity') else "unknown"
            html.append("            <tr>")
            html.append(f"                <td>{vuln.vuln_id}</td>")
            html.append(f"                <td>{vuln.name}</td>")
            html.append(f"                <td class='{severity_class}'>{vuln.severity}</td>")
            html.append(f"                <td>{vuln.cvss_score or 'N/A'}</td>")
            html.append(f"                <td>{ip}</td>")
            html.append("            </tr>")
        
        html.append("        </table>")
        
        # Detalles por host
        html.append("        <h2>Detalles por Host</h2>")
        
        for ip, vulnerabilities in scan_results.items():
            html.append(f"        <div class='host'>")
            html.append(f"            <h3>Host: {ip}</h3>")
            
            # Añadir información adicional del host si está disponible
            if hosts_info and ip in hosts_info:
                host = hosts_info[ip]
                if hasattr(host, 'hostname') and host.hostname:
                    html.append(f"            <p><strong>Hostname:</strong> {host.hostname}</p>")
                if hasattr(host, 'os_info') and host.os_info:
                    os_name = host.os_info.get('name', 'Unknown')
                    html.append(f"            <p><strong>Sistema Operativo:</strong> {os_name}</p>")
                
                # Listar puertos abiertos
                if hasattr(host, 'ports'):
                    open_ports = [p for p in host.ports if p.state == 'open']
                    if open_ports:
                        port_list = ", ".join([f"{p.number}/{p.protocol}" for p in open_ports[:10]])
                        if len(open_ports) > 10:
                            port_list += f" y {len(open_ports) - 10} más"
                        html.append(f"            <p><strong>Puertos abiertos:</strong> {port_list}</p>")
            
            # Listar vulnerabilidades
            html.append(f"            <h4>Vulnerabilidades encontradas: {len(vulnerabilities)}</h4>")
            
            # Ordenar por severidad (Critical primero)
            severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Unknown": 4}
            sorted_vulns = sorted(
                vulnerabilities,
                key=lambda v: severity_order.get(v.severity if hasattr(v, 'severity') else "Unknown", 5)
            )
            
            for vuln in sorted_vulns:
                severity_class = vuln.severity.lower() if hasattr(vuln, 'severity') else "unknown"
                html.append(f"            <div class='vulnerability {severity_class}'>")
                html.append(f"                <h4>{vuln.vuln_id} - {vuln.name}</h4>")
                html.append(f"                <p><strong>Severidad:</strong> {vuln.severity}</p>")
                if vuln.cvss_score is not None:
                    html.append(f"                <p><strong>CVSS:</strong> {vuln.cvss_score}</p>")
                if vuln.description:
                    html.append(f"                <p><strong>Descripción:</strong> {vuln.description[:200]}...</p>")
                
                # Sistemas afectados específicos
                if hasattr(vuln, 'affected_systems') and vuln.affected_systems:
                    html.append("                <p><strong>Afecta a:</strong></p>")
                    html.append("                <ul>")
                    for system in vuln.affected_systems[:3]:  # Limitar a 3 sistemas
                        service_info = system.get('service', '')
                        port_info = f":{system.get('port')}" if system.get('port') else ''
                        html.append(f"                    <li>{service_info}{port_info}</li>")
                    if len(vuln.affected_systems) > 3:
                        html.append(f"                    <li>Y {len(vuln.affected_systems) - 3} servicios más</li>")
                    html.append("                </ul>")
                
                # Mitigación
                if vuln.mitigation:
                    html.append(f"                <p><strong>Mitigación:</strong> {vuln.mitigation}</p>")
                
                # Referencias
                if hasattr(vuln, 'references') and vuln.references:
                    html.append("                <p><strong>Referencias:</strong></p>")
                    html.append("                <ul>")
                    for ref in vuln.references[:3]:  # Limitar a 3 referencias
                        html.append(f"                    <li><a href='{ref}' target='_blank'>{ref}</a></li>")
                    if len(vuln.references) > 3:
                        html.append(f"                    <li>Y {len(vuln.references) - 3} referencias más</li>")
                    html.append("                </ul>")
                
                html.append("            </div>")
            
            html.append("        </div>")
        
        # Recomendaciones
        html.append("        <h2>Recomendaciones</h2>")
        html.append("        <ol>")
        html.append("            <li>Priorizar la mitigación de vulnerabilidades críticas y altas.</li>")
        html.append("            <li>Actualizar el software y sistemas operativos a las últimas versiones.</li>")
        html.append("            <li>Implementar un programa regular de parcheo de seguridad.</li>")
        html.append("            <li>Revisar y fortalecer las configuraciones de seguridad.</li>")
        html.append("            <li>Realizar escaneos de vulnerabilidades periódicos.</li>")
        html.append("        </ol>")
        
        # Pie de página
        html.append("        <div style='margin-top: 50px; text-align: center; color: #777;'>")
        html.append("            <p>Informe generado automáticamente por la Herramienta de Ciberseguridad</p>")
        html.append("        </div>")
        
        html.append("    </div>")
        html.append("</body>")
        html.append("</html>")
        
        # Guardar informe
        with open(output_file, 'w') as f:
            f.write("\n".join(html))
            
        self.logger.info(f"Informe HTML guardado en {output_file}")
        return output_file
        
    def _generate_severity_chart(self, scan_results, output_dir):
        """
        Genera un gráfico de distribución de vulnerabilidades por severidad.
        
        Args:
            scan_results (dict): Resultados del escaneo por host
            output_dir (str): Directorio para guardar el gráfico
            
        Returns:
            str: Ruta del archivo generado o None si hay error
        """
        try:
            # Contar vulnerabilidades por severidad
            severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Unknown": 0}
            for host_vulns in scan_results.values():
                for vuln in host_vulns:
                    severity = vuln.severity if hasattr(vuln, 'severity') else "Unknown"
                    if severity in severity_counts:
                        severity_counts[severity] += 1
                    else:
                        severity_counts["Unknown"] += 1
            
            # Crear figura
            plt.figure(figsize=(8, 6))
            
            # Preparar datos
            labels = list(severity_counts.keys())
            sizes = list(severity_counts.values())
            colors = ['#ff5252', '#ff9800', '#ffeb3b', '#4caf50', '#9e9e9e']
            
            # Crear gráfico de pastel
            plt.pie(sizes, labels=None, autopct='%1.1f%%', startangle=140, colors=colors)
            plt.axis('equal')
            plt.title("Distribución de Vulnerabilidades por Severidad")
            
            # Añadir leyenda
            plt.legend(labels, loc="best", bbox_to_anchor=(1, 0.5))
            
            # Guardar figura
            output_path = os.path.join(output_dir, "severity_distribution.png")
            plt.tight_layout()
            plt.savefig(output_path, dpi=300, bbox_inches='tight')
            plt.close()
            
            return output_path
            
        except Exception as e:
            self.logger.error(f"Error al crear gráfico de severidad: {str(e)}")
            return None
            
    def _generate_host_vulnerabilities_chart(self, scan_results, output_dir):
        """
        Genera un gráfico de vulnerabilidades por host.
        
        Args:
            scan_results (dict): Resultados del escaneo por host
            output_dir (str): Directorio para guardar el gráfico
            
        Returns:
            str: Ruta del archivo generado o None si hay error
        """
        try:
            # Contar vulnerabilidades por host y severidad
            host_data = {}
            for ip, vulns in scan_results.items():
                host_data[ip] = {
                    "Critical": 0,
                    "High": 0,
                    "Medium": 0,
                    "Low": 0,
                    "Unknown": 0
                }
                
                for vuln in vulns:
                    severity = vuln.severity if hasattr(vuln, 'severity') else "Unknown"
                    if severity in host_data[ip]:
                        host_data[ip][severity] += 1
                    else:
                        host_data[ip]["Unknown"] += 1
            
            # Limitar a los 10 hosts con más vulnerabilidades
            host_vuln_counts = [(ip, sum(data.values())) for ip, data in host_data.items()]
            host_vuln_counts.sort(key=lambda x: x[1], reverse=True)
            top_hosts = [ip for ip, _ in host_vuln_counts[:10]]
            
            # Crear figura
            plt.figure(figsize=(10, 6))
            
            # Preparar datos
            categories = ["Critical", "High", "Medium", "Low", "Unknown"]
            colors = ['#ff5252', '#ff9800', '#ffeb3b', '#4caf50', '#9e9e9e']
            
            # Crear barras apiladas
            bottom = np.zeros(len(top_hosts))
            
            for i, category in enumerate(categories):
                values = [host_data[ip][category] for ip in top_hosts]
                plt.bar(top_hosts, values, bottom=bottom, label=category, color=colors[i])
                bottom += values
            
            plt.title("Vulnerabilidades por Host")
            plt.xlabel("Host")
            plt.ylabel("Número de Vulnerabilidades")
            plt.xticks(rotation=45, ha='right')
            plt.legend()
            plt.grid(axis='y', linestyle='--', alpha=0.7)
            
            # Guardar figura
            output_path = os.path.join(output_dir, "host_vulnerabilities.png")
            plt.tight_layout()
            plt.savefig(output_path, dpi=300)
            plt.close()
            
            return output_path
            
        except Exception as e:
            self.logger.error(f"Error al crear gráfico de hosts: {str(e)}")
            return None
            
    def generate_json_report(self, scan_results, hosts_info=None, output_file=None):
        """
        Genera un informe en formato JSON sobre las vulnerabilidades encontradas.
        
        Args:
            scan_results (dict): Resultados del escaneo por host
            hosts_info (dict, opcional): Información adicional sobre los hosts
            output_file (str, opcional): Ruta del archivo de salida
            
        Returns:
            str: Ruta del archivo generado
        """
        self.logger.info("Generando informe JSON")
        
        # Preparar nombre de archivo si no se especifica
        if output_file is None:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = os.path.join(self.output_dir, f"vulnerability_report_{timestamp}.json")
            
        # Preparar datos
        report_data = {
            "metadata": {
                "generated_at": datetime.datetime.now().isoformat(),
                "hosts_scanned": len(scan_results),
                "total_vulnerabilities": sum(len(vulns) for vulns in scan_results.values())
            },
            "hosts": {}
        }
        
        # Añadir datos por host
        for ip, vulnerabilities in scan_results.items():
            host_data = {
                "ip_address": ip,
                "vulnerabilities": [vuln.to_dict() for vuln in vulnerabilities]
            }
            
            # Añadir información adicional del host si está disponible
            if hosts_info and ip in hosts_info:
                host = hosts_info[ip]
                if hasattr(host, 'hostname'):
                    host_data["hostname"] = host.hostname
                if hasattr(host, 'os_info'):
                    host_data["os_info"] = host.os_info
                if hasattr(host, 'ports'):
                    host_data["ports"] = [port.to_dict() for port in host.ports]
                    
            report_data["hosts"][ip] = host_data
            
        # Guardar informe
        with open(output_file, 'w') as f:
            json.dump(report_data, f, indent=4, default=str)
            
        self.logger.info(f"Informe JSON guardado en {output_file}")
        return output_file
        
    def generate_complete_report(self, scan_results, hosts_info=None, output_dir=None):
        """
        Genera un conjunto completo de informes en diferentes formatos.
        
        Args:
            scan_results (dict): Resultados del escaneo por host
            hosts_info (dict, opcional): Información adicional sobre los hosts
            output_dir (str, opcional): Directorio para guardar los informes
            
        Returns:
            dict: Diccionario con rutas de los archivos generados
        """
        if output_dir:
            self.output_dir = output_dir
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)
        
        self.logger.info(f"Generando conjunto completo de informes para {len(scan_results)} hosts")
        
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = f"vulnerability_report_{timestamp}"
        
        report_files = {}
        
        # Generar informes en diferentes formatos
        text_report = self.generate_text_report(
            scan_results, 
            hosts_info, 
            os.path.join(self.output_dir, f"{base_name}.txt")
        )
        report_files['text'] = text_report
        
        html_report = self.generate_html_report(
            scan_results, 
            hosts_info, 
            os.path.join(self.output_dir, f"{base_name}.html")
        )
        report_files['html'] = html_report
        
        json_report = self.generate_json_report(
            scan_results, 
            hosts_info, 
            os.path.join(self.output_dir, f"{base_name}.json")
        )
        report_files['json'] = json_report
        
        self.logger.info(f"Conjunto completo de informes generado en {self.output_dir}")
        return report_files
