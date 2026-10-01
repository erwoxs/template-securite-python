from typing import Counter
from unittest.mock import patch
from tp1.utils.capture import Capture
from scapy.all import TCP,UDP,ARP, Ether, IP
from scapy.layers.dns import  DNS
from scapy.layers.inet import ICMP


def test_capture_init():
    # When
    capture = Capture()
    assert capture.interface != "" #Test si interface nest pas vide
    assert capture.packets == []
    assert capture.summary == ""
    assert capture.protocols == Counter()


def test_given_capture_when_capture_traffic_then_interface_is_set():
    # Given
    capture = Capture()

    # When
    capture.capture_traffic()

    # Then
    # This is a minimal test since the method doesn't do much yet
    assert capture.interface == ""


def test_sort_network_protocols():
    # Given
    capture = Capture()

    # When
    result = capture.sort_network_protocols()

    # Then
    assert result == ""  # Method currently returns None


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

    # When
    result = capture._gen_summary()

    # Then
    assert result == ""  # Method currently returns empty string
