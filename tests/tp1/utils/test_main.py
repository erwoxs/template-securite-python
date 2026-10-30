import sys
from unittest.mock import patch, MagicMock
from tp1.main import main


def test_main(monkeypatch):
    #Given
    monkeypatch.setattr(sys, "argv", ["tp1", "--pcap", "test.pcap", "--out", "out.json"])

    #When
    with patch("tp1.main.Capture") as mock_capture, \
         patch("tp1.main.Report") as mock_report:
        main()

    #Then : main a bien utilise Capture et Report
    mock_capture.assert_called_once()
    mock_report.assert_called_once()