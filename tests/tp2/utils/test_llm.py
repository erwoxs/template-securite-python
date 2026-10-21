import json
from tp2.utils.llm import LLMTriage
from unittest.mock import patch, MagicMock

def test_fallback(tmp_path):
    #Given
    summary = json.dumps({
        "meta": {"entropy": 5.0},
        "iocs": {"urls": ["http://evil.test"], "ips": ["1.2.3.4"]},
        "yara": ["Rule1"],
    })
    llm = LLMTriage("ollama")

    #When
    verdict = llm._fallback(summary)

    #Then
    assert verdict["score_0_10"] == 5
    assert verdict["famille"] == "suspect"


def test_call_llm(monkeypatch):
    #Given
    monkeypatch.setenv("OPENROUTER_API_KEY", "fake-key")

    fausse_reponse = MagicMock()
    fausse_reponse.json.return_value = {
        "choices": [{"message": {"content": '{"famille": "dropper", "score_0_10": 8}'}}]
    }

    llm = LLMTriage("openrouter")

    #When
    with patch("tp2.utils.llm.requests.post", return_value=fausse_reponse):
        verdict = llm._call_llm("{}")

    #Then
    assert verdict["famille"] == "dropper"
    assert verdict["score_0_10"] == 8


def test_triage(monkeypatch):
    #Given
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    summary = json.dumps({
        "meta": {"entropy": 5.0},
        "iocs": {"urls": ["http://evil.test"]},
        "yara": ["Rule1"],
    })
    llm = LLMTriage("openrouter")

    #When
    verdict = llm.triage(summary)

    #Then
    assert "famille" in verdict
    assert "score_0_10" in verdict