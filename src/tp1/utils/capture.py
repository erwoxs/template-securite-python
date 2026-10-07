from scapy.layers.inet import ICMP
from scapy.sendrecv import sniff
from tp1.utils.lib import choose_interface
from tp1.utils.config import logger
from collections import Counter
from scapy.all import TCP,UDP,ARP, Ether, IP
from scapy.layers.dns import  DNS



class Capture:
    def __init__(self) -> None:
        self.interface = choose_interface()
        self.packets =[]
        self.summary = ""
        #self.interface = "wlp0s20f3"
        self.protocols = Counter() #Attribut

    def capture_traffic(self,pcap=None) -> None:
        """
        Capture le traffic sur une interface ou sur un pcap
        """

        if pcap:
            logger.info(f"Lecture du fichier {pcap}")
            self.packets = sniff(offline=pcap)
        else:
            interface = self.interface
            logger.info(f"Capture traffic from interface {interface}")
            self.packets = sniff(iface=self.interface, timeout=30)

    def sort_network_protocols(self) -> list:
        """
        Trie par quantité le nombre de protocoles dans le traffic
        """
        return self.protocols.most_common()

    def get_all_protocols(self) -> str:
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
                if pkt[TCP].dport == 80 or pkt[TCP].sport == 80: #Compte paquets http src et dst
                    protocols["HTTP"] += 1
            if pkt.haslayer(UDP):
                protocols["UDP"] += 1
            if pkt.haslayer(ICMP):
                protocols["ICMP"] += 1
            if pkt.haslayer(DNS):
                protocols["DNS"] += 1
        self.protocols = protocols #liste des paquets dans protocols
        logger.info(f"Captured protocols: {protocols}")
        return protocols

    def analyse(self, protocols: str) -> None:
        """
        Analyse all captured data and return statement
        Si un tra c est illégitime (exemple : Injection SQL, ARP
        Spoo ng, etc)
        a Noter la tentative d'attaque.
        b Relever le protocole ainsi que l'adresse réseau/physique
        de l'attaquant.
        c (FACULTATIF) Opérer le blocage de la machine
        attaquante.
        Sinon a cher que tout va bien
        """
        all_protocols = self.get_all_protocols()
        sort = self.sort_network_protocols()
        logger.debug(f"All protocols: {all_protocols}")
        logger.debug(f"Sorted protocols: {sort}")

        self.summary = self._gen_summary()

    def get_summary(self) -> str:
        """
        Return summary
        :return:
        """
        return self.summary

    def _gen_summary(self) -> str:
        """
        Generate summary
        """
        summary = ""
        return summary
