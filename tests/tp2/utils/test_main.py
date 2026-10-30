import sys
from unittest.mock import patch, MagicMock
from tp2 import main as main_module


def test_main(tmp_path, monkeypatch):
    #Given
    samples = tmp_path / "samples"
    samples.mkdir()
    (samples / "test.bin").write_bytes(b"data")

    rules = tmp_path / "rules"
    rules.mkdir()

    out = tmp_path / "out"

    #on simule les arguments de la ligne de commande
    monkeypatch.setattr(sys, "argv", [
        "tp2",
        "--samples", str(samples),
        "--rules", str(rules),
        "--out", str(out),
    ])

    #When
    with patch("tp2.main.Triage") as mock_triage, \
         patch("tp2.main.Report") as mock_report:
        mock_triage.return_value.run.return_value = {"sha256": "abc"}
        main_module.main()

    #Then
    mock_triage.assert_called()
    mock_report.assert_called()