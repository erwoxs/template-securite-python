from tp2.utils.sample import Sample


def test_get_file_metadata(tmp_path):
    # Given
    fichier = tmp_path / "test.bin" #crée un fichier de test avec un contenu connu
    fichier.write_bytes(b"hello world")
    sample = Sample(str(fichier))

    # When
    meta = sample.get_file_metadata()

    # Then
    assert meta["size"] == 11          #hello world fait 11 octets
    assert "sha256" in meta
    assert "md5" in meta
    assert "file_type" in meta
    assert "entropy" in meta