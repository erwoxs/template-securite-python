# TP1 - IDS/IPS

## Lancement avec poetry
poetry install
poetry run tp1 --pcap capture.pcap --out report.json

## Objectif de cet outil
Analyse un PCAP, compte les protocoles, détecte ARP spoofing,
scan de ports et injection SQL, et génère un report.json + un PDF et une vue graphique
