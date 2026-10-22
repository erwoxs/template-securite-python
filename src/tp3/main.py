"""TP3 - Breach the target (squelette).

Enchaîne une phase web (fuzzing + CAPTCHA) et une phase réseau (décodage
chronométré). Voir tp3-breach-the-target.md.

    poetry run tp3 --target http://127.0.0.1:8080
"""

import argparse
from pathlib import Path
import requests
from tp3.utils.config import logger
from tp3.utils.session import Session
import base64
from pwn import remote


def fuzz_endpoint(target: str) -> str:
    """Test de la wordlist"""
    wordlist = Path(__file__).parent / "wordlist.txt"
    for ligne in wordlist.read_text().splitlines():
        mot = ligne.strip()
        if not mot:
            continue
        r = requests.get(f"{target}/{mot}")
        if r.status_code != 404:
            return mot
    return ""


def breach_web(target: str) -> tuple[str, int, bytes]:
    """Fuzz les endpoints, casse le CAPTCHA, retourne (host, port, key)."""
    path = fuzz_endpoint(target) #fuzz la cible pour trouver le endpoint
    session = Session(f"{target}/{path}")
    session.prepare_request() #recupère le cookie
    session.submit_request() #recupère le body json
    session.process_response() #extrait le flag du json

    logger.info(f"FLAG1: {session.get_flag()}") #affiche le flag recupere

    result = session.result
    host = result["host"]
    port = result["port"]
    key = bytes.fromhex(result["key"])
    return host, port, key

def xor_bytes(data: bytes, key: bytes) -> bytes:
    """XOR octet par octet"""
    return bytes(c ^ key[i % len(key)] for i, c in enumerate(data))

def breach_network(host: str, port: int, key: bytes) -> str:
    """Se connecte au service TCP, decode chaque round, retourne le flag final."""
    conn = remote(host, port) #ouvre une connexion tcp
    conn.recvline()

    for _ in range(3):
        encode = conn.recvline().strip()
        brut = base64.b64decode(encode) #decode bas64 pour le XOR
        token = xor_bytes(brut, key)
        conn.sendline(token)

    reponse = conn.recvline().decode()
    conn.close()

    flag = reponse.replace("OK", "").strip()
    return flag




def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="http://127.0.0.1:8080")
    args = ap.parse_args()

    logger.info("Starting TP3 - breach the target")
    host, port, key = breach_web(args.target)
    flag = breach_network(host, port, key)
    logger.info(f"FLAG_FINAL: {flag}")


if __name__ == "__main__":
    main()
