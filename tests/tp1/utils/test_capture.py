from collections import Counter
from unittest.mock import patch
from tp1.utils.capture import Capture
from scapy.all import TCP,UDP,ARP, Ether, IP, Raw
from scapy.layers.dns import  DNS
from scapy.layers.inet import ICMP


def test_capture_init():
    # When
    capture = Capture()
    assert capture.interface != "" #Test si interface nest pas vide
    assert capture.packets == []
    assert capture.summary == ""
    assert capture.protocols == Counter()


def test_capture_traffic():
    # Given
    capture = Capture()
    f_paquets = [Ether() / IP() / TCP()]

    # When  remplace sniff par un faux qui renvoie des paquets
    with patch("tp1.utils.capture.sniff", return_value=f_paquets) as mock_sniff:
        capture.capture_traffic(pcap="fichier.pcap")

    # Then
    assert capture.packets == f_paquets
    mock_sniff.assert_called_once()


"""def test_given_capture_when_capture_traffic_then_interface_is_set():
    # Given
    capture = Capture()

    # When
    capture.capture_traffic()

    # Then
    # This is a minimal test since the method doesn't do much yet
    assert capture.interface == """


def test_sort_network_protocols():
    # Given
    capture = Capture()
    capture.protocols = Counter({"UDP": 12, "TCP": 95, "ARP": 20})

    # When
    result = capture.sort_network_protocols()

    # Then
    assert result == [("TCP", 95), ("ARP",20),("UDP",12) ]  #Résultat attendu


def test_get_all_protocols():
    # Given
    capture = Capture()
    capture.packets = [ #Crée des pacquets fictifs
        Ether() / IP() / TCP(dport=80),
        Ether() / IP() / TCP(dport=443),
        Ether() / IP() / UDP() / DNS(),
        Ether() / IP() / ICMP(),
        Ether() / ARP(),
    ]
    # When
    result = capture.get_all_protocols() #Test de la fonction get_all_protocol
    # Then
    assert result["ETHERNET"] == 5
    assert result["IP"] == 4 #résultats attendu du nbre de paquet ip
    assert result["TCP"] == 2 #résultat attendu du nbre de paquets tcp
    assert result["HTTP"] == 1
    assert result["UDP"] == 1
    assert result["DNS"] == 1
    assert result["ICMP"] == 1
    assert result["ARP"] == 1


def test_analyse():
    # Given
    capture = Capture()

    # When
    with (
        patch.object(capture, "get_all_protocols") as mock_get_protocols,
        patch.object(capture, "sort_network_protocols") as mock_sort,
        patch.object(capture, "_gen_summary") as mock_gen_summary,
    ):
        mock_gen_summary.return_value = "Test summary"
        capture.analyse("tcp")

    # Then
    mock_get_protocols.assert_called_once()
    mock_sort.assert_called_once()
    mock_gen_summary.assert_called_once()
    assert capture.summary == "Test summary"

def test_detect_arp():
    capture = Capture()
    capture.attacks = []
    capture.packets = [
        Ether() / ARP(op=2, psrc="192.168.1.1", hwsrc="aa:aa:aa:aa:aa:aa"),
        Ether() / ARP(op=2, psrc="192.168.1.1", hwsrc="bb:bb:bb:bb:bb:bb"),
]
    # When
    capture._detect_arp()

    # Then
    assert {"type": "arp_spoofing", "attacker": "bb:bb:bb:bb:bb:bb"} in capture.attacks


def test_detect_arp():
    capture = Capture()
    capture.attacks = []
    capture.packets = [
        Ether() / ARP(op=2, psrc="192.168.1.1", hwsrc="aa:aa:aa:aa:aa:aa"),   #vraie machine
        Ether() / ARP(op=2, psrc="192.168.1.1", hwsrc="bb:bb:bb:bb:bb:bb"),   #attaquant
        Ether() / ARP(op=2, psrc="192.168.1.1", hwsrc="bb:bb:bb:bb:bb:bb"),
        Ether() / ARP(op=2, psrc="192.168.1.1", hwsrc="bb:bb:bb:bb:bb:bb"),
    ]
    capture._detect_arp()
    assert {"type": "arp_spoofing", "attacker": "bb:bb:bb:bb:bb:bb"} in capture.attacks

def test_detect_sql():
    # Given : une requete HTTP contenant une injection SQL
    capture = Capture()
    capture.attacks = []
    capture.packets = [
        IP(src="10.0.0.9") / TCP(dport=80) / Raw(load=b"GET /login?user=admin' or 1=1 HTTP/1.1")
    ]
    # When
    capture._detect_sql()

    # Then
    assert {"type": "sql_injection", "attacker": "10.0.0.9"} in capture.attacks


def test_get_summary():
    # Given
    capture = Capture()
    capture.summary = "Test summary"

    # When
    result = capture.get_summary()

    # Then
    assert result == "Test summary"


def test_gen_summary():
    # Given
    capture = Capture()
    capture.attacks = []
    # When
    result = capture._gen_summary([("TCP", 95)])
    # Then
    assert "Aucune attaque" in result
