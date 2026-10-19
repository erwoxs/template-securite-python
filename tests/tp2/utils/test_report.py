import json
from tp2.utils.report import Report


def test_generate_json(tmp_path):
    #Given
    result = {"sha256": "abc", "score": 8}
    report = Report(result)
    out = tmp_path / "out.json"

    #When
    report.generate_json(str(out))

    #Then
    data = json.loads(out.read_text())
    assert data == result

def test_generate_pdf(tmp_path):
    #Given
    report = Report({"sha256": "abc", "score": 8})
    out = tmp_path / "out.pdf"

    #When
    report.generate_pdf(str(out))

    #Then
    assert out.exists()
    assert out.stat().st_size > 0