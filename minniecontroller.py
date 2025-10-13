# Simple Shortest Path First Controller in Ryu - Version corrigée
# Copyright (C) 2020  Shih-Hao Tseng <shtseng@caltech.edu>
# 
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program. If not, see <https://www.gnu.org/licenses/>.
#
# references/sources:
# http://csie.nqu.edu.tw/smallko/sdn/ryu_sp13.htm
# http://106.15.204.80/2017/05/18/RYU%E5%A4%84%E7%90%86ARP%E5%8D%8F%E8%AE%AE/

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import mac
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet, ethernet, arp, ether_types
from collections import defaultdict, Counter
from ryu.topology.api import get_switch, get_link
from ryu.app.wsgi import ControllerBase
from ryu.topology import event, switches
from ryu.lib.packet import ipv4
# Pour gérer les stations WiFi
from ryu.topology import event

import networkx as nx
import time
 

class FlowRule:
    """Représente une règle de flux avec source, destination et port de sortie"""
    def __init__(self, src, dst, out_port, priority=1):
        self.src = src
        self.dst = dst
        self.out_port = out_port
        self.priority = priority
        self.is_wildcard_src = src == '*'
        self.is_wildcard_dst = dst == '*'
    
    def __str__(self):
        return f"({self.src}, {self.dst}, {self.out_port})"
    
    def __repr__(self):
        return self.__str__()

   
class RoutingTable:
    """Table de routage avec compression MINNIE"""
    def __init__(self, dpid, max_size=10):
        self.dpid = dpid
        self.rules = []
        self.max_size = max_size
        self.compression_count = 0
    
    def add_rule(self, src, dst, out_port, priority=1):
        """Ajouter une règle à la table"""
        rule = FlowRule(src, dst, out_port, priority)
        self.rules.append(rule)
    
    def get_port_for_flow(self, src, dst):
        """Récupérer le port de sortie pour un flux donné"""
        # Trier par priorité (plus haute d'abord)
        sorted_rules = sorted(self.rules, key=lambda r: r.priority, reverse=True)
        
        for rule in sorted_rules:
            if self._matches_rule(rule, src, dst):
                return rule.out_port
        return None
    
    def _matches_rule(self, rule, src, dst):
        """Vérifier si une règle correspond à un flux"""
        src_match = rule.src == '*' or rule.src == src
        dst_match = rule.dst == '*' or rule.dst == dst
        return src_match and dst_match
    
    def is_full(self):
        """Vérifier si la table est pleine"""
        return len(self.rules) >= self.max_size
    
    def compress_by_destination(self):
        """Compression par agrégation destination (technique 2)"""
        compressed_rules = []
        dest_ports = defaultdict(list)
        
        # Grouper les règles par destination
        for rule in self.rules:
            if not rule.is_wildcard_dst:
                dest_ports[rule.dst].append(rule.out_port)
        
        # Pour chaque destination, trouver le port le plus fréquent
        for dst, ports in dest_ports.items():
            if len(ports) > 1:  # Compression possible
                port_counter = Counter(ports)
                most_common_port = port_counter.most_common(1)[0][0]
                
                # Ajouter règle wildcard pour cette destination
                compressed_rules.append(FlowRule('*', dst, most_common_port, priority=2))
                
                # Garder les règles spécifiques pour les autres ports
                for rule in self.rules:
                    if rule.dst == dst and rule.out_port != most_common_port:
                        compressed_rules.append(FlowRule(rule.src, rule.dst, rule.out_port, priority=3))
            else:
                # Garder les règles originales si pas de compression possible
                for rule in self.rules:
                    if rule.dst == dst:
                        compressed_rules.append(rule)
        
        # Ajouter les autres règles
        for rule in self.rules:
            if rule.is_wildcard_dst or rule.dst not in dest_ports:
                compressed_rules.append(rule)
        
        # Nettoyer les doublons exacts
        unique = {}
        for r in compressed_rules:
            key = (r.src, r.dst, r.out_port)
            if key not in unique:  
                unique[key] = r
        return list(unique.values())

    def minnie_compress(self):
        """Appliquer uniquement la compression MINNIE par destination"""
        compressed_by_dst = self.compress_by_destination()
        
        # On applique le résultat de la compression par destination
        self.rules = compressed_by_dst
        self.compression_count += 1
        
        return len(compressed_by_dst)

class WcnController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
 
    def __init__(self, *args, **kwargs):
        super(WcnController, self).__init__(*args, **kwargs)
        self.topology_api_app = self
        self.net = nx.DiGraph()
        self.nodes = {}
        self.links = {}
        self.no_of_nodes = 0
        self.no_of_links = 0
        self.i = 0
        self.arp_table = {}
        self.ip_to_datapath = {}
        self.dpid_to_datapath = {}
        self.routing_tables = {}
        self.original_routing_tables = {}  # Table originale
        self.compression_threshold = 80  # Seuil de compression (80% de la table)
        self.stations = set()
        self.connected_stations = {}  # Dictionnaire pour tracker les stations
    def add_flow(self, datapath, src, dst, out_port):
        """Ajouter une règle de flux IPv4 spécifique"""
        self.logger.info("Installing flow rule: SRC=%s, DST=%s, OUT_PORT=%s on DPID=%s", 
                         src, dst, out_port, datapath.id)
        
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Match sur les adresses IPv4
        match = parser.OFPMatch(
            eth_type=0x0800,  # IPv4
            ipv4_src=src, 
            ipv4_dst=dst
        )
        
        actions = [parser.OFPActionOutput(out_port)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        
        mod = parser.OFPFlowMod(
            datapath=datapath,
            match=match,
            cookie=0,
            command=ofproto.OFPFC_ADD,
            priority=100,  
            instructions=inst
        )
        
        datapath.send_msg(mod)

    def add_flow_c(self, datapath, priority, match, actions, buffer_id=None):
        """Ajouter une règle de flux au switch"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)


    def check_and_compress_table(self, dpid):
        """Vérifier et compresser la table si nécessaire en utilisant la table originale"""
        if dpid not in self.routing_tables or dpid not in self.original_routing_tables:
            return
        
        original_table = self.original_routing_tables[dpid]  # Table originale
        compressed_table = self.routing_tables[dpid]         # Table compressée

        # Compression basée sur le nombre de règles
        if len(original_table.rules) >= 13:
            old_size = len(compressed_table.rules)
            # On vide la table compressée avant d'insérer les nouvelles règles
            compressed_table.rules = []
            # Copier toutes les règles originales dans la table compressée
            compressed_table.rules = original_table.rules.copy()
            # Appliquer la compression MINNIE sur les règles copiées
            new_size = compressed_table.minnie_compress()
            self.logger.info(
                "COMPRESSION DÉCLENCHÉE - DPID=%s: %d -> %d règles, gain=%d règles",
                dpid, old_size, new_size, old_size - new_size
            )
            
            # Réinstaller les règles compressées sur le switch
            self.reinstall_compressed_rules(dpid)

    def reinstall_compressed_rules(self, dpid):
        """Réinstaller les règles compressées sur le switch"""
        # Obtenir le datapath du switch
        if dpid not in self.dpid_to_datapath:
            self.logger.error("DPID %s not found in datapath mapping", dpid)
            return
            
        datapath = self.dpid_to_datapath[dpid]
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Supprimer toutes les règles IPv4 existantes (priorité 100)
        match = parser.OFPMatch(eth_type=0x0800)
        mod = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            match=match,
            priority=100
        )
        datapath.send_msg(mod)

        # Attendre un peu pour que la suppression soit effective
        time.sleep(0.05)

        # Réinstaller les règles compressées
        table = self.routing_tables[dpid]
        
        self.logger.info("===== Réinstallation des règles du switch %s =====", dpid)
        
        for i, rule in enumerate(table.rules):
            self.logger.info("Installing compressed rule %d: SRC=%s, DST=%s, OUT_PORT=%s, PRIORITY=%s", 
                            i, rule.src, rule.dst, rule.out_port, rule.priority)
            
            # Construire le match en fonction des wildcards
            if rule.src != '*' and rule.dst != '*':
                match = parser.OFPMatch(eth_type=0x0800, ipv4_src=rule.src, ipv4_dst=rule.dst)
            elif rule.src != '*':
                match = parser.OFPMatch(eth_type=0x0800, ipv4_src=rule.src)
            elif rule.dst != '*':
                match = parser.OFPMatch(eth_type=0x0800, ipv4_dst=rule.dst)
            else:
                match = parser.OFPMatch(eth_type=0x0800)  # Règle par défaut IPv4
            
            actions = [parser.OFPActionOutput(rule.out_port)]
            
            # Utiliser une priorité plus élevée pour les règles compressées
            priority = 150 + rule.priority
            
            self.add_flow_c(datapath, priority, match, actions)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Installer une règle par défaut pour envoyer au contrôleur
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        
        mod = parser.OFPFlowMod(
            datapath=datapath,
            match=match,
            cookie=0,
            command=ofproto.OFPFC_ADD,
            idle_timeout=0,
            hard_timeout=0,
            priority=0,  # Priorité la plus basse
            instructions=inst
        )
        datapath.send_msg(mod)

        dpid = datapath.id
        self.routing_tables[dpid] = RoutingTable(dpid)
        self.original_routing_tables[dpid] = RoutingTable(dpid)  
        self.logger.info("Switch %s connected, routing table initialized", dpid)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        pkt = packet.Packet(msg.data)
        eth_hdr = pkt.get_protocol(ethernet.ethernet)

        if not eth_hdr:
            return
        
        # Filtrer LLDP
        if eth_hdr.ethertype == 0x88cc:
            return

        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        dst = eth_hdr.dst
        src = eth_hdr.src

        # ARP
        if eth_hdr.ethertype == 0x0806:
            self.arp_handler(
                pkt=pkt,
                src=src,
                dst=dst,
                datapath=datapath,
                dpid=dpid,
                ofproto=ofproto,
                parser=parser,
                in_port=in_port
            )
            return

        # IPv4 routing
        if eth_hdr.ethertype == 0x0800:
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            if not ip_pkt:
                return
                
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst
            
            self.logger.info("IPv4 packet received: %s -> %s on DPID=%s port=%s", 
                           src_ip, dst_ip, dpid, in_port)
            
            # Ajouter le noeud source à la topologie s'il n'existe pas
            if src_ip not in self.net:
                self.net.add_node(src_ip)
                self.net.add_edge(dpid, src_ip, port=in_port)
                self.net.add_edge(src_ip, dpid)
                self.logger.info("Added new node %s connected to DPID=%s on port=%s", 
                               src_ip, dpid, in_port)
            
            self.ipv4_routing(
                msg=msg,
                src=src_ip,
                dst=dst_ip,
                datapath=datapath,
                dpid=dpid,
                ofproto=ofproto,
                parser=parser,
                in_port=in_port
            )
            return

    def arp_handler(self, pkt, src, dst, datapath, dpid, ofproto, parser, in_port):
        arp_hdr = pkt.get_protocol(arp.arp)
        if not arp_hdr:
            return

        arp_src_ip = arp_hdr.src_ip
        arp_dst_ip = arp_hdr.dst_ip
        eth_src = src
        eth_dst = dst

        # Vérification du port edge
        if self.is_edge_port(dpid, in_port):  
            if arp_src_ip in self.ip_to_datapath:
                old_dp, old_port = self.ip_to_datapath[arp_src_ip]
                old_dpid = old_dp.id

                if old_dpid != dpid or old_port != in_port:
                    print(f"[MOVE] {arp_src_ip} a migré "
                        f"de (DPID={old_dpid}, port={old_port}) → (DPID={dpid}, port={in_port})")
                    self.invalidate_flows_for_host(arp_src_ip)
                
            # Mise à jour de la table : on stocke datapath + port
            self.ip_to_datapath[arp_src_ip] = (datapath, in_port)

        # Topologie pour le routage
        if arp_src_ip not in self.net:
            self.net.add_node(arp_src_ip)
            self.net.add_edge(dpid, arp_src_ip, port=in_port)
            self.net.add_edge(arp_src_ip, dpid)

        # Mise à jour de la table ARP
        self.arp_table[arp_src_ip] = eth_src

        # Gestion ARP
        if arp_hdr.opcode == arp.ARP_REQUEST:
            if arp_dst_ip in self.arp_table:
                # Réponse ARP
                eth_dst = self.arp_table[arp_dst_ip]
                ARP_Reply = packet.Packet()
                ARP_Reply.add_protocol(ethernet.ethernet(
                    ethertype=0x0806,
                    dst=eth_src,
                    src=eth_dst))
                ARP_Reply.add_protocol(arp.arp(
                    opcode=arp.ARP_REPLY,
                    src_mac=eth_dst,
                    src_ip=arp_dst_ip,
                    dst_mac=eth_src,
                    dst_ip=arp_src_ip))
                ARP_Reply.serialize()

                actions = [parser.OFPActionOutput(in_port)]
                out = parser.OFPPacketOut(
                    datapath=datapath,
                    buffer_id=ofproto.OFP_NO_BUFFER,
                    in_port=ofproto.OFPP_CONTROLLER,
                    actions=actions,
                    data=ARP_Reply.data)
                datapath.send_msg(out)
                return True
            else:
                # Diffuser la requête ARP
                for sw_datapath in self.dpid_to_datapath.values():
                    if sw_datapath == datapath:
                        continue
                    actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
                    out = parser.OFPPacketOut(
                        datapath=sw_datapath,
                        buffer_id=ofproto.OFP_NO_BUFFER,
                        in_port=ofproto.OFPP_CONTROLLER,
                        actions=actions,
                        data=pkt.data)
                    sw_datapath.send_msg(out)

        elif arp_hdr.opcode == arp.ARP_REPLY:
            if arp_dst_ip in self.ip_to_datapath:
                target_dp, target_port = self.ip_to_datapath[arp_dst_ip]
                ARP_Reply = packet.Packet()
                actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
                out = parser.OFPPacketOut(
                    datapath=target_dp,
                    buffer_id=ofproto.OFP_NO_BUFFER,
                    in_port=ofproto.OFPP_CONTROLLER,
                    actions=actions,
                    data=ARP_Reply.data)
                target_dp.send_msg(out)
                return True

        return False

    def ipv4_routing(self, msg, src, dst, datapath, dpid, ofproto, parser, in_port):
        if dst not in self.net:
            self.logger.info("Destination %s not in network, flooding", dst)
            out_port = ofproto.OFPP_FLOOD
        else:
            self.logger.info("Routing from %s to %s", src, dst)
            self.logger.debug("Network nodes: %s", list(self.net.nodes))
            self.logger.debug("Network edges: %s", list(self.net.edges))

            try:
                path = nx.shortest_path(self.net, src, dst)
                self.logger.info("Shortest path: %s", path)
                
                path_len = len(path)
                
                # Trouver l'index du DPID actuel dans le chemin
                try:
                    current_index = path.index(dpid)
                except ValueError:
                    self.logger.error("Current DPID %s not found in path", dpid)
                    out_port = ofproto.OFPP_FLOOD
                else:
                    # Installer les règles sur tous les switches du chemin
                    i = current_index
                    while i < path_len - 1:
                        current_node = path[i]
                        next_node = path[i + 1]
                        
                        # Ignorer si le noeud actuel n'est pas un switch
                        if current_node not in self.dpid_to_datapath:
                            i += 1
                            continue
                        
                        # Trouver le port de sortie vers le noeud suivant
                        if self.net.has_edge(current_node, next_node):
                            edge_data = self.net[current_node][next_node]
                            if 'port' in edge_data:
                                out_port_for_switch = edge_data['port']
                                
                                # --- AJOUT DANS LES DEUX TABLES ---
                                if current_node not in self.original_routing_tables:
                                    self.original_routing_tables[current_node] = RoutingTable(current_node)
                                if current_node not in self.routing_tables:
                                    self.routing_tables[current_node] = RoutingTable(current_node)

                                # Toujours ajouter dans original_routing_tables (historique)
                                self.original_routing_tables[current_node].add_rule(src, dst, out_port_for_switch)

                                # Par défaut on ajoute aussi dans routing_tables (avant compression)
                                self.routing_tables[current_node].add_rule(src, dst, out_port_for_switch)

                                self.logger.info("Added rule to ORIGINAL DPID=%s: %s->%s via port %s", 
                                               current_node, src, dst, out_port_for_switch)
                                self.logger.debug("Also added to ACTIVE DPID=%s", current_node)
                                
                                # Vérifier et compresser si nécessaire (contrôle basé sur original_routing_tables)
                                self.check_and_compress_table(current_node)
                                
                                # Installer la règle sur le switch
                                if current_node in self.dpid_to_datapath:
                                    switch_datapath = self.dpid_to_datapath[current_node]
                                    self.add_flow(
                                        datapath=switch_datapath,
                                        src=src,
                                        dst=dst,
                                        out_port=out_port_for_switch
                                    )
                                
                                # Si c'est le switch d'entrée, sauvegarder le port de sortie
                                if current_node == dpid:
                                    out_port = out_port_for_switch
                        
                        i += 1
                    
                    # Si on n'a pas trouvé de port de sortie pour le switch d'entrée
                    if 'out_port' not in locals():
                        self.logger.warning("No output port found for DPID=%s, flooding", dpid)
                        out_port = ofproto.OFPP_FLOOD

            except nx.NetworkXNoPath:
                self.logger.warning("No path found from %s to %s", src, dst)
                out_port = ofproto.OFPP_FLOOD
            except Exception as e:
                self.logger.error("Error in routing: %s", str(e))
                out_port = ofproto.OFPP_FLOOD

        # Envoyer le paquet
        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions
        )
        datapath.send_msg(out)



    @set_ev_cls(event.EventSwitchEnter)
    def switch_enter(self, ev):
        datapath = ev.switch.dp
        dpid = datapath.id
        if dpid not in self.dpid_to_datapath:
            self.dpid_to_datapath[dpid] = datapath
        self.net.add_node(dpid)
        self.logger.info("Switch %s entered network", dpid)
    
    @set_ev_cls(event.EventSwitchLeave)
    def switch_leave(self, ev):
        datapath = ev.switch.dp
        dpid = datapath.id
        if dpid in self.dpid_to_datapath:
            del self.dpid_to_datapath[dpid]
        if self.net.has_node(dpid):
            self.net.remove_node(dpid)
        self.logger.info("Switch %s left network", dpid)

    @set_ev_cls(event.EventLinkAdd)
    def link_add(self, ev):
        src_port_no = ev.link.src.port_no
        src_dpid = ev.link.src.dpid
        dst_dpid = ev.link.dst.dpid
        self.net.add_edge(src_dpid, dst_dpid, port=src_port_no)
        self.links[(src_dpid, src_port_no)] = (dst_dpid, ev.link.dst.port_no)  # stocker le lien
        self.logger.info("Link added: %s (port %s) -> %s", src_dpid, src_port_no, dst_dpid)

    def is_edge_port(self, dpid, port_no):
        # Si le port est dans self.links comme port source -> c'est inter-switch
        return (dpid, port_no) not in self.links

    @set_ev_cls(event.EventHostAdd)
    def host_join(self, ev):
        host = ev.host
        dpid = None
        port_no = None
        if hasattr(host, 'port'):
            dpid = host.port.dpid
            port_no = host.port.port_no
        print(f"[JOIN] Station {host.mac} connectée sur switch DPID={dpid}, port={port_no}")

    @set_ev_cls(event.EventHostDelete)
    def host_leave(self, ev):
        host = ev.host
        print(f"[LEAVE] Station {host.mac} disparue")

    @set_ev_cls(event.EventHostMove)
    def host_move(self, ev):
        host = ev.host
        old_port = ev.port_old
        new_port = ev.port_new
        print(f"[MOVE] Station {host.mac} a changé de switch/port : "
              f"{old_port.dpid}:{old_port.port_no} → {new_port.dpid}:{new_port.port_no}")
                
    def invalidate_flows_for_host(self, host_ip):
        """Supprimer toutes les règles contenant host_ip comme source ou destination dans TOUTES les tables"""
        self.logger.info("Invalidating flows for host IP %s", host_ip)

        # 1️⃣ Supprimer le nœud du graphe
        if self.net.has_node(host_ip):
            print("Avant suppression:", list(self.net.nodes), list(self.net.edges))
            self.net.remove_node(host_ip)
            print("Après suppression:", list(self.net.nodes), list(self.net.edges))
            print(f"Nœud {host_ip} supprimé du graphe")

        # 2️⃣ Parcourir toutes les tables de routage (COMPRESSÉES ET ORIGINALES)
        for dpid in list(self.routing_tables.keys()):
            rules_to_remove_from_switch = []
            
            # ===== TABLE COMPRESSÉE =====
            if dpid in self.routing_tables:
                table = self.routing_tables[dpid]
                rules_to_remove = [rule for rule in table.rules if rule.src == host_ip or rule.dst == host_ip]
                
                # Supprimer les règles de la table compressée
                table.rules = [rule for rule in table.rules if rule not in rules_to_remove]
                rules_to_remove_from_switch.extend(rules_to_remove)
                
                self.logger.info("Removed %d rules from compressed table on DPID=%s", 
                            len(rules_to_remove), dpid)
            
            # ===== TABLE ORIGINALE =====
            if dpid in self.original_routing_tables:
                orig_table = self.original_routing_tables[dpid]
                orig_rules_to_remove = [rule for rule in orig_table.rules if rule.src == host_ip or rule.dst == host_ip]
                
                # Supprimer les règles de la table originale
                orig_table.rules = [rule for rule in orig_table.rules if rule not in orig_rules_to_remove]
                
                # Ajouter à la liste pour suppression du switch (éviter les doublons)
                for orig_rule in orig_rules_to_remove:
                    # Vérifier si une règle similaire n'est pas déjà dans la liste
                    if not any(r.src == orig_rule.src and r.dst == orig_rule.dst 
                            for r in rules_to_remove_from_switch):
                        rules_to_remove_from_switch.append(orig_rule)
                
                self.logger.info("Removed %d rules from original table on DPID=%s", 
                            len(orig_rules_to_remove), dpid)

            # 3️⃣ Supprimer les règles du switch physique
            if dpid in self.dpid_to_datapath and rules_to_remove_from_switch:
                datapath = self.dpid_to_datapath[dpid]
                parser = datapath.ofproto_parser
                ofproto = datapath.ofproto

                # Méthode optimisée : supprimer par source et destination globalement
                # Supprimer toutes les règles avec host_ip comme source
                match_src = parser.OFPMatch(eth_type=0x0800, ipv4_src=host_ip)
                mod_src = parser.OFPFlowMod(
                    datapath=datapath,
                    command=ofproto.OFPFC_DELETE,
                    out_port=ofproto.OFPP_ANY,
                    out_group=ofproto.OFPG_ANY,
                    match=match_src
                )
                datapath.send_msg(mod_src)
                self.logger.info("Deleted all flows with SRC=%s on DPID=%s", host_ip, dpid)
                
                # Supprimer toutes les règles avec host_ip comme destination
                match_dst = parser.OFPMatch(eth_type=0x0800, ipv4_dst=host_ip)
                mod_dst = parser.OFPFlowMod(
                    datapath=datapath,
                    command=ofproto.OFPFC_DELETE,
                    out_port=ofproto.OFPP_ANY,
                    out_group=ofproto.OFPG_ANY,
                    match=match_dst
                )
                datapath.send_msg(mod_dst)
                self.logger.info("Deleted all flows with DST=%s on DPID=%s", host_ip, dpid)

        # 4️⃣ Nettoyer les autres structures de données
        if host_ip in self.arp_table:
            del self.arp_table[host_ip]
            self.logger.info("Removed %s from ARP table", host_ip)
        
        if host_ip in self.ip_to_datapath:
            del self.ip_to_datapath[host_ip]
            self.logger.info("Removed %s from IP-to-datapath mapping", host_ip)

        self.logger.info("Finished invalidating flows for host %s", host_ip)
