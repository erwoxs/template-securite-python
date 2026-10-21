# TP1 - IDS/IPS

## Lancement avec poetry
poetry install

poetry run tp1 --pcap capture.pcap --out report.json

## Description
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

# TP3 - Breach the target

## Description
Exploit automatise qui enchaine une phase web (fuzzing d'endpoint + resolution
de CAPTCHA par OCR) et une phase reseau (decodage base64 + XOR chronometre)
pour recuperer deux drapeaux sur une cible.

## Installation
poetry install

## Utilisation
poetry run tp3 --target http://localhost:8080

## Fonctionnement
- Phase web : trouve la page cachee, casse le CAPTCHA, recupere flag1 + host/port/cle
- Phase reseau : se connecte au service TCP, decode les jetons sous 5s par round
- Affiche les deux drapeaux (FLAG1 et FLAG_FINAL)
