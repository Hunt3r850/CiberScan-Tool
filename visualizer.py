"""
Clase NetworkVisualizer para visualizar redes escaneadas.

Esta clase proporciona métodos para generar visualizaciones gráficas
de las redes escaneadas, incluyendo mapas de red y gráficos de puertos.
"""

import networkx as nx
import matplotlib.pyplot as plt
import os
import logging
from matplotlib.colors import LinearSegmentedColormap
import numpy as np

class NetworkVisualizer:
    def __init__(self, output_dir="./output", log_level=logging.INFO):
        """
        Inicializa un nuevo objeto NetworkVisualizer.
        
        Args:
            output_dir (str, opcional): Directorio para guardar las visualizaciones
            log_level (int, opcional): Nivel de logging
        """
        self.output_dir = output_dir
        self.logger = self._setup_logger(log_level)
        
        # Crear directorio de salida si no existe
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
    def _setup_logger(self, log_level):
        """
        Configura el logger para el visualizador.
        
        Args:
            log_level (int): Nivel de logging
            
        Returns:
            Logger: Objeto logger configurado
        """
        logger = logging.getLogger("NetworkVisualizer")
        logger.setLevel(log_level)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            
        return logger
        
    def create_network_map(self, hosts, filename="network_map.png", title="Mapa de Red"):
        """
        Crea un mapa visual de la red basado en los hosts escaneados.
        
        Args:
            hosts (list): Lista de objetos Host
            filename (str, opcional): Nombre del archivo de salida
            title (str, opcional): Título del gráfico
            
        Returns:
            str: Ruta del archivo generado o None si hay error
        """
        self.logger.info(f"Creando mapa de red con {len(hosts)} hosts")
        
        try:
            # Crear grafo
            G = nx.Graph()
            
            # Colores para diferentes tipos de nodos
            host_color = "#6495ED"  # Azul para hosts
            service_color = "#FF7F50"  # Coral para servicios
            
            # Añadir nodos de hosts
            for host in hosts:
                if host.status == "up":
                    label = f"{host.ip_address}"
                    if host.hostname:
                        label += f"\n({host.hostname})"
                    
                    G.add_node(host.ip_address, 
                              type='host', 
                              label=label,
                              color=host_color)
                    
                    # Añadir nodos de servicios y conexiones
                    for port in host.ports:
                        if port.state == "open" and port.service:
                            service_id = f"{host.ip_address}:{port.number}"
                            service_label = f"{port.service.name}\n{port.number}/{port.protocol}"
                            
                            G.add_node(service_id, 
                                      type='service', 
                                      label=service_label,
                                      color=service_color)
                            
                            G.add_edge(host.ip_address, service_id)
            
            # Si no hay nodos, no se puede crear el gráfico
            if len(G.nodes) == 0:
                self.logger.warning("No hay hosts activos para visualizar")
                return None
                
            # Crear figura
            plt.figure(figsize=(12, 10))
            
            # Posicionar nodos
            pos = nx.spring_layout(G, k=0.3, iterations=50)
            
            # Dibujar nodos
            node_colors = [G.nodes[n]['color'] for n in G.nodes]
            nx.draw_networkx_nodes(G, pos, node_color=node_colors, node_size=1500, alpha=0.8)
            
            # Dibujar etiquetas
            labels = {n: G.nodes[n]['label'] for n in G.nodes}
            nx.draw_networkx_labels(G, pos, labels=labels, font_size=8)
            
            # Dibujar conexiones
            nx.draw_networkx_edges(G, pos, width=1.0, alpha=0.5)
            
            plt.title(title)
            plt.axis('off')
            
            # Guardar figura
            output_path = os.path.join(self.output_dir, filename)
            plt.tight_layout()
            plt.savefig(output_path, dpi=300, bbox_inches='tight')
            plt.close()
            
            self.logger.info(f"Mapa de red guardado en {output_path}")
            return output_path
            
        except Exception as e:
            self.logger.error(f"Error al crear mapa de red: {str(e)}")
            return None
            
    def create_port_distribution(self, hosts, filename="port_distribution.png", top_n=20):
        """
        Crea un gráfico de distribución de puertos abiertos.
        
        Args:
            hosts (list): Lista de objetos Host
            filename (str, opcional): Nombre del archivo de salida
            top_n (int, opcional): Número de puertos más comunes a mostrar
            
        Returns:
            str: Ruta del archivo generado o None si hay error
        """
        self.logger.info(f"Creando distribución de puertos para {len(hosts)} hosts")
        
        try:
            # Contar puertos abiertos
            port_counts = {}
            for host in hosts:
                for port in host.ports:
                    if port.state == "open":
                        port_key = f"{port.number}/{port.protocol}"
                        if port_key in port_counts:
                            port_counts[port_key] += 1
                        else:
                            port_counts[port_key] = 1
            
            # Si no hay puertos, no se puede crear el gráfico
            if not port_counts:
                self.logger.warning("No hay puertos abiertos para visualizar")
                return None
                
            # Ordenar por frecuencia y tomar los top_n
            sorted_ports = sorted(port_counts.items(), key=lambda x: x[1], reverse=True)
            top_ports = sorted_ports[:top_n]
            
            # Crear figura
            plt.figure(figsize=(12, 8))
            
            # Preparar datos
            ports = [p[0] for p in top_ports]
            counts = [p[1] for p in top_ports]
            
            # Crear gráfico de barras
            bars = plt.bar(ports, counts)
            
            # Colorear barras según frecuencia
            cm = plt.cm.get_cmap('YlOrRd')
            max_count = max(counts)
            for i, bar in enumerate(bars):
                bar.set_color(cm(counts[i]/max_count))
            
            plt.title("Distribución de Puertos Abiertos")
            plt.xlabel("Puerto/Protocolo")
            plt.ylabel("Número de Hosts")
            plt.xticks(rotation=45, ha='right')
            plt.grid(axis='y', linestyle='--', alpha=0.7)
            
            # Guardar figura
            output_path = os.path.join(self.output_dir, filename)
            plt.tight_layout()
            plt.savefig(output_path, dpi=300)
            plt.close()
            
            self.logger.info(f"Distribución de puertos guardada en {output_path}")
            return output_path
            
        except Exception as e:
            self.logger.error(f"Error al crear distribución de puertos: {str(e)}")
            return None
            
    def create_service_distribution(self, hosts, filename="service_distribution.png", top_n=15):
        """
        Crea un gráfico de distribución de servicios detectados.
        
        Args:
            hosts (list): Lista de objetos Host
            filename (str, opcional): Nombre del archivo de salida
            top_n (int, opcional): Número de servicios más comunes a mostrar
            
        Returns:
            str: Ruta del archivo generado o None si hay error
        """
        self.logger.info(f"Creando distribución de servicios para {len(hosts)} hosts")
        
        try:
            # Contar servicios
            service_counts = {}
            for host in hosts:
                for port in host.ports:
                    if port.state == "open" and port.service:
                        service_name = port.service.name
                        if service_name in service_counts:
                            service_counts[service_name] += 1
                        else:
                            service_counts[service_name] = 1
            
            # Si no hay servicios, no se puede crear el gráfico
            if not service_counts:
                self.logger.warning("No hay servicios detectados para visualizar")
                return None
                
            # Ordenar por frecuencia y tomar los top_n
            sorted_services = sorted(service_counts.items(), key=lambda x: x[1], reverse=True)
            top_services = sorted_services[:top_n]
            
            # Crear figura
            plt.figure(figsize=(10, 8))
            
            # Preparar datos para gráfico de pastel
            labels = [s[0] for s in top_services]
            sizes = [s[1] for s in top_services]
            
            # Añadir categoría "Otros" si hay más servicios
            if len(sorted_services) > top_n:
                others_sum = sum([s[1] for s in sorted_services[top_n:]])
                labels.append("Otros")
                sizes.append(others_sum)
            
            # Crear gráfico de pastel
            plt.pie(sizes, labels=None, autopct='%1.1f%%', startangle=140,
                   colors=plt.cm.Paired(np.linspace(0, 1, len(labels))))
            
            plt.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle
            plt.title("Distribución de Servicios Detectados")
            
            # Añadir leyenda
            plt.legend(labels, loc="best", bbox_to_anchor=(1, 0.5))
            
            # Guardar figura
            output_path = os.path.join(self.output_dir, filename)
            plt.tight_layout()
            plt.savefig(output_path, dpi=300, bbox_inches='tight')
            plt.close()
            
            self.logger.info(f"Distribución de servicios guardada en {output_path}")
            return output_path
            
        except Exception as e:
            self.logger.error(f"Error al crear distribución de servicios: {str(e)}")
            return None
            
    def create_os_distribution(self, hosts, filename="os_distribution.png"):
        """
        Crea un gráfico de distribución de sistemas operativos detectados.
        
        Args:
            hosts (list): Lista de objetos Host
            filename (str, opcional): Nombre del archivo de salida
            
        Returns:
            str: Ruta del archivo generado o None si hay error
        """
        self.logger.info(f"Creando distribución de sistemas operativos para {len(hosts)} hosts")
        
        try:
            # Contar sistemas operativos
            os_counts = {}
            for host in hosts:
                if host.os_info and 'name' in host.os_info:
                    os_name = host.os_info['name']
                    
                    # Simplificar nombres de OS para mejor visualización
                    for key in ['Windows', 'Linux', 'macOS', 'FreeBSD', 'Cisco', 'Android']:
                        if key in os_name:
                            os_name = key
                            break
                    
                    if os_name in os_counts:
                        os_counts[os_name] += 1
                    else:
                        os_counts[os_name] = 1
                else:
                    # Contar hosts sin OS detectado
                    if "Unknown" in os_counts:
                        os_counts["Unknown"] += 1
                    else:
                        os_counts["Unknown"] = 1
            
            # Si no hay datos, no se puede crear el gráfico
            if not os_counts:
                self.logger.warning("No hay información de sistemas operativos para visualizar")
                return None
                
            # Crear figura
            plt.figure(figsize=(10, 6))
            
            # Preparar datos
            os_names = list(os_counts.keys())
            counts = list(os_counts.values())
            
            # Crear gráfico de barras horizontales
            bars = plt.barh(os_names, counts)
            
            # Colorear barras
            cm = plt.cm.get_cmap('viridis')
            for i, bar in enumerate(bars):
                bar.set_color(cm(i/len(bars)))
            
            plt.title("Distribución de Sistemas Operativos")
            plt.xlabel("Número de Hosts")
            plt.ylabel("Sistema Operativo")
            plt.grid(axis='x', linestyle='--', alpha=0.7)
            
            # Añadir valores en las barras
            for i, v in enumerate(counts):
                plt.text(v + 0.1, i, str(v), va='center')
            
            # Guardar figura
            output_path = os.path.join(self.output_dir, filename)
            plt.tight_layout()
            plt.savefig(output_path, dpi=300)
            plt.close()
            
            self.logger.info(f"Distribución de sistemas operativos guardada en {output_path}")
            return output_path
            
        except Exception as e:
            self.logger.error(f"Error al crear distribución de sistemas operativos: {str(e)}")
            return None
            
    def generate_report(self, hosts, output_dir=None):
        """
        Genera un informe visual completo con todos los gráficos.
        
        Args:
            hosts (list): Lista de objetos Host
            output_dir (str, opcional): Directorio para guardar el informe
            
        Returns:
            dict: Diccionario con rutas de los archivos generados
        """
        if output_dir:
            self.output_dir = output_dir
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)
        
        self.logger.info(f"Generando informe visual para {len(hosts)} hosts")
        
        report_files = {}
        
        # Generar todos los gráficos
        network_map = self.create_network_map(hosts)
        if network_map:
            report_files['network_map'] = network_map
            
        port_dist = self.create_port_distribution(hosts)
        if port_dist:
            report_files['port_distribution'] = port_dist
            
        service_dist = self.create_service_distribution(hosts)
        if service_dist:
            report_files['service_distribution'] = service_dist
            
        os_dist = self.create_os_distribution(hosts)
        if os_dist:
            report_files['os_distribution'] = os_dist
            
        self.logger.info(f"Informe visual generado con {len(report_files)} gráficos")
        return report_files
