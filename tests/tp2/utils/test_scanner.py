from tp2.utils.scanner import YaraScanner


def test_yara_scan(tmp_path):
    #Given
    regle = tmp_path / "test.yar" #crée un fichier yar temporaire
    regle.write_text('rule Test_Rule { strings: $a = "malware" condition: $a }')
    scanner = YaraScanner(str(regle))

    #When
    result = scanner.scan(b"malware")

    #Then
    assert "Test_Rule" in result