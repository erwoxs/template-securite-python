from scapy.layers.inet import ICMP
from scapy.sendrecv import sniff
from tp1.utils.lib import choose_interface
from tp1.utils.config import logger
from collections import Counter
from scapy.all import TCP, UDP, ARP, Ether, IP, Raw
from scapy.layers.dns import DNS
from urllib.parse import unquote_plus
import re


class Capture:
    def __init__(self) -> None:
        self.interface = choose_interface()
        self.packets = []
        self.summary = ""
        self.protocols = Counter()
        self.attacks = []
        self.flag = None

    def capture_traffic(self, pcap=None) -> None:
        """
        Capture le traffic sur une interface ou sur un pcap
        """
        if pcap:
            logger.info(f"Lecture du fichier {pcap}")
            self.packets = sniff(offline=pcap)
        else:
            logger.info(f"Capture traffic from interface {self.interface}")
            self.packets = sniff(iface=self.interface, timeout=30)

    def sort_network_protocols(self) -> list:
        """
        Trie par quantité le nombre de protocoles dans le traffic
        """
        return self.protocols.most_common()

    def get_all_protocols(self) -> Counter:
        """
        Retourne nombre de paquets par protocoles
        """
        protocols = Counter()
        for pkt in self.packets:
            if pkt.haslayer(Ether):
                protocols["ETHERNET"] += 1
            if pkt.haslayer(ARP):
                protocols["ARP"] += 1
            if pkt.haslayer(IP):
                protocols["IP"] += 1
            if pkt.haslayer(TCP):
                protocols["TCP"] += 1
                if pkt[TCP].dport == 80 or pkt[TCP].sport == 80:
                    protocols["HTTP"] += 1
            if pkt.haslayer(UDP):
                protocols["UDP"] += 1
            if pkt.haslayer(ICMP):
                protocols["ICMP"] += 1
            if pkt.haslayer(DNS):
                protocols["DNS"] += 1
        self.protocols = protocols
        logger.info(f"Protocoles capturés: {protocols}")
        return protocols

    def analyse(self, protocols: str = None) -> None:
        """Detecte les attaques dans le trafic"""
        self.get_all_protocols() #Compte les protocoles présents
        sort = self.sort_network_protocols() #Triage des protocoles par rapport au nbre de paquets

        self.attacks = [] #Liste vide pour detections des attaques
        self._detect_arp() #Utilise detect_arp pour trouver des atatques arp
        self._detect_scan()
        self._detect_sql() #Utilise detect_sql pour trouver des attaques sql

        self.summary = self._gen_summary(sort) #Rapport

    def _detect_arp(self) -> None:
        """Une IP pour deux MAC = spoofing"""
        table_arp = {} #Dictionnaire pour table ARP
        for pkt in self.packets:
            if not (pkt.haslayer(ARP) and pkt[ARP].op == 2): #Si pas de réponse ARP, pkt suivant
                continue
            ip, mac = pkt[ARP].psrc, pkt[ARP].hwsrc #Recupè l'ip source et mac source
            if ip not in table_arp: #si ip nest pas dans la table arp
                table_arp[ip] = mac #MAC/IP connue
            elif table_arp[ip] != mac:  # IP déjà connue avec une autre addr MAC
                attaque = {"type": "arp_spoofing", "attacker": mac}
                if attaque not in self.attacks:  #Supprime les doublons
                    self.attacks.append(attaque)

    def _detect_scan(self) -> None:
        """Envoie de scan SYN vers trop de ports"""
        ports_syn = {} #Dictionnaire pour le nombre de port d'un scan SYN
        for pkt in self.packets: #Parcoure chaque pakets
            if not (pkt.haslayer(IP) and pkt.haslayer(TCP)): #Si pas IP/TCP, passer au pkt suivant
                continue
            flags = int(pkt[TCP].flags) #Recupère les flag TCP du paquet
            if flags & 0x02 and not flags & 0x10: #Si flag SYN(0x02) et non SYN-ACK(0x10)
                ports_syn.setdefault(pkt[IP].src, set()).add(pkt[TCP].dport) #Stocke tout les ports pour chaque IP

        for ip, ports in ports_syn.items():
            if len(ports) > 15: #Si nbre de port >15
                self.attacks.append({"type": "port_scan", "attacker": ip}) #detection port scan

    def _detect_sql(self) -> None:
        """Motifs d'injection SQL dans le HTTP et flag cacher"""
        motifs = ["' or ", "or 1=1", "union select", "'--", "' --", "drop table"] #Pattern sql suspect
        for pkt in self.packets:
            if not (pkt.haslayer(TCP) and pkt.haslayer(Raw) and pkt[TCP].dport == 80): #Si pas de pkt TCP/80 suivant
                continue
            brut = pkt[Raw].load.decode(errors="ignore") #Recupère requete http du paquet
            data = unquote_plus(brut).lower() #Décode l'url pour chercher une injection sql encoder

            if self.flag is None:
                trouve = re.search(r"ESGI\{[^}]*\}", brut) #cherche le flag
                if trouve:
                    self.flag = trouve.group() #si flag trouver

            if any(m in data for m in motifs):
                attaque = {"type": "sql_injection", "attacker": pkt[IP].src}
                if attaque not in self.attacks:
                    self.attacks.append(attaque)




    def _gen_summary(self, sort) -> str:
        """Résumé des attaques"""
        resume = f"Protocoles : {sort}\n"  #Recupère les protocoles trié
        if self.attacks:
            resume += f"{len(self.attacks)} attaque detecte\n" #Ajoute une ligne par attaque
            for a in self.attacks:
                logger.warning(f"{a['type']} - attaquant : {a['attacker']}")
                resume += f"- {a['type']} | {a['attacker']}\n"
        else:
            logger.info("Aucune attaque detectee")
            resume += "Aucune attaque trouvée\n"
        if self.flag:
            resume += f"Flag : {self.flag}\n"
        return resume


    def get_summary(self) -> str:
        """Retourne le resume de l'analyse"""
        return self.summary