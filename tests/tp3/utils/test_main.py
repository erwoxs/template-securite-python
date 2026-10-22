from unittest.mock import patch, MagicMock
from tp3.main import fuzz_endpoint
from tp3.main import breach_web
from tp3.main import breach_network, xor_bytes
import base64


def test_fuzz_endpoint():
    #Given
    def fausse_reponse(url):
        r = MagicMock()
        r.status_code = 200 if "internal-panel" in url else 404
        return r

    #When : on remplace requests.get par notre faux
    with patch("tp3.main.requests.get", side_effect=fausse_reponse):
        result = fuzz_endpoint("http://test")

    #Then
    assert result == "internal-panel"


def test_breach_web():
    #Given
    faux_session = MagicMock()  #fausse session
    faux_session.get_flag.return_value = "ESGI{web_test}"
    faux_session.result = {"host": "127.0.0.1", "port": 9090, "key": "ff00"}

    #When
    with patch("tp3.main.fuzz_endpoint", return_value="internal-panel"), \
         patch("tp3.main.Session", return_value=faux_session):
        host, port, key = breach_web("http://test")

    #Then
    assert host == "127.0.0.1"
    assert port == 9090
    assert key == bytes.fromhex("ff00")


def test_breach_network():
    #Given
    key = b"\xff\x19\x3b\x22"
    token = b"abcd1234abcd1234"

    faux_conn = MagicMock()
    #le serveur envoie 3 rounds encodes suivi du le flag
    ligne_encodee = base64.b64encode(xor_bytes(token, key))
    faux_conn.recvline.side_effect = [
        b"intro\n",
        ligne_encodee, ligne_encodee, ligne_encodee,
        b"OK ESGI{chain_test}\n",
    ]

    #When
    with patch("tp3.main.remote", return_value=faux_conn):
        flag = breach_network("127.0.0.1", 9090, key)

    #Then
    assert flag == "ESGI{chain_test}"

def test_xor_bytes():
    #Given
    data = b"hello"
    key = b"\xff\x19\x3b\x22"

    #When
    encode = xor_bytes(data, key) #xor deux fois avec la meme key
    decode = xor_bytes(encode, key)

    #Then
    assert decode == data
    assert encode != data