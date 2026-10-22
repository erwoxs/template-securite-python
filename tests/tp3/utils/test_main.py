from unittest.mock import patch, MagicMock
from tp3.main import fuzz_endpoint
from tp3.main import breach_web
from tp3.main import  breach_network

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