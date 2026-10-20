from tp2.utils.triage import Triage


def test_triage_run(tmp_path):
    #Given
    sample_file = tmp_path / "sample.bin"
    sample_file.write_bytes(b"connect c2.evil.test http://evil.test/x.php")

    rules_file = tmp_path / "rules.yar"
    rules_file.write_text('rule Test { strings: $a = "evil" condition: $a }')

    triage = Triage(str(sample_file), "ollama")
    triage.scanner.rules_path = str(rules_file)   #règles yara de test

    #When
    result = triage.run()

    #Then
    assert "sha256" in result
    assert "iocs" in result
    assert "yara_matches" in result