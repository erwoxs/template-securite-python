# TP1 - IDS/IPS

## Lancement avec poetry
poetry install

poetry run tp1 --pcap capture.pcap --out report.json

## Objectif de cet outil
Analyse un PCAP, compte les protocoles, détecte ARP spoofing,
scan de ports et injection SQL, et génère un report.json + un PDF et une vue graphique


# TP2 - Triage de malware

## Description
Outil d'analyse statique de fichiers suspects. Il lit un échantillon
sans l'exécuter, en extrait les métadonnées, les indicateurs de
compromission (IOC) et les correspondances YARA, puis demande un
verdict à un modèle de langage. 
Produit un rapport JSON et PDF.

## Installation
poetry install

## Utilisation
poetry run tp2 --samples DOSSIER --rules DOSSIER --out DOSSIER

- --samples : dossier des échantillons à analyser
- --rules : dossier des règles YARA
- --out : dossier de sortie (un JSON par échantillon)

## Fonctionnement
- Métadonnées : SHA-256, MD5, taille, type de fichier, entropie
- IOC : domaines, IP, URLs, mutex, clés de registre
- YARA : règles fournies et règles personnalisées
- LLM : verdict (famille, capacités, score) à partir d'un résumé
- Rapport : fichier JSON et PDF par échantillon
