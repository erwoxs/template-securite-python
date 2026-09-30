from scapy.layers.inet import ICMP
from scapy.sendrecv import sniff
from tp1.utils.lib import choose_interface
from tp1.utils.config import logger
from collections import Counter
from scapy.all import TCP,UDP,ARP



class Capture:
    def __init__(self) -> None:
        self.interface = choose_interface()
        self.packets =[]
        self.summary = ""
        self.protocols = Counter() #attribut

    def capture_traffic(self) -> None:
        """
        Capture network traffic from an interface
        """
        interface = self.interface
        logger.info(f"Capture traffic from interface {interface}")
        self.packets = sniff(iface=self.interface, timeout=30)


    def sort_network_protocols(self) -> str:
        """
        Sort and return all captured network protocols
        """
        return ""

    def get_all_protocols(self) -> str:
        """
        Return all protocols captured with total packets number
        """
        protocols = Counter()
        for pkt in self.packets: #Parcours des paquets
            if pkt.haslayer(TCP):
                protocols["TCP"] += 1 #Compte chaque paquet tcp
            if pkt.haslayer(UDP):
                protocols["UDP"] += 1
            if pkt.haslayer(ARP):
                protocols["ARP"] += 1
            if pkt.haslayer(ICMP):
                protocols["ICMP"] += 1
        self.protocols = protocols #liste des paquets dans protocols
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
