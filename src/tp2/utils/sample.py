import hashlib
import math
import re
from collections import Counter

import lief
import magic


class Sample:
    def __init__(self, path: str) -> None:
        self.path = path
        with open(path, "rb") as f:
            self.data = f.read()

    def get_file_metadata(self) -> dict:
        """sha256, md5, taille, type de fichier, entropie de Shannon."""
        metadata = {
            "sha256": hashlib.sha256(self.data).hexdigest(),
            "md5": hashlib.md5(self.data).hexdigest(),  #crée un objet qui calcule le md5
            "size": len(self.data), #compte le nbre d'octets du fichier
            "file_type": magic.from_buffer(self.data), #analyse le fichier et renvoie le type
          "entropy": round(self.shannon_entropy(), 2),
        }
        return metadata




    def shannon_entropy(self) -> float:
        if not self.data:
            return 0.0
        freq = Counter(self.data)
        n = len(self.data)
        return -sum((c / n) * math.log2(c / n) for c in freq.values())

    def extract_iocs(self) -> dict:
        """domaines, ips, urls, mutex, registry (regex sur les strings)."""
        strings = re.findall(rb"[\x20-\x7e]{4,}", self.data)
        text = b" ".join(strings).decode(errors="ignore")

        return {
            "domains": re.findall(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", text, re.IGNORECASE), #regex pour nom de domaine
            "ips": re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text),
            "urls": re.findall(r"https?://[^\s\"']+", text),
            "mutex": re.findall(r"(?:Global|Local)\\[A-Za-z0-9_.-]+", text),
            "registry": re.findall(r"HK(?:LM|CU|CR|U|CC)\\[A-Za-z0-9\\_.-]+", text), #regex pour clé de registre
        }

    def parse_binary(self) -> dict:
        """imports / sections via lief (si PE/ELF)."""
        binary = lief.parse(self.path) #import lief lit le binaire
        if binary is None: #si lief ne parse rien, retourne des listes vides
            return {"imports": [], "sections": []}

        imports = [f.name for f in binary.imported_functions] #parcours chaque fonctions du binaire
        sections = [s.name for s in binary.sections] #parcours chaque sections du binaire

        return {"imports": imports, "sections": sections}

    def extract_flag(self) -> str:
        """Retrouve le vrai flag dans les samples"""
        text = self.data.decode(errors="ignore")

        for m in re.finditer(r"ESGI\{[^}]*\}", text): #cherche tout les flags ESGI
            avant = text[max(0, m.start() - 10):m.start()]
            if "FLAG=" in avant:
                return m.group()
        return ""


