from unittest.mock import patch, MagicMock
from tp3.main import fuzz_endpoint


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