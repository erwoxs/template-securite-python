from tp2.utils.sample import Sample
import re

def test_get_file_metadata(tmp_path):
    #Given
    fichier = tmp_path / "test.bin" #crée un fichier de test avec un contenu connu
    fichier.write_bytes(b"hello world")
    sample = Sample(str(fichier))

    #When
    meta = sample.get_file_metadata()

    #Then
    assert meta["size"] == 11          #hello world fait 11 octets
    assert "sha256" in meta
    assert "md5" in meta
    assert "file_type" in meta
    assert "entropy" in meta


def test_extract_iocs(tmp_path):
    #Given
    #Ajout de IOCS fictif
    fichier = tmp_path / "test.bin"
    fichier.write_bytes(b"connect c2.evil.test 185.10.20.30 http://evil.test/x.php")
    sample = Sample(str(fichier))

    #When
    iocs = sample.extract_iocs()

    #Then
    assert "c2.evil.test" in iocs["domains"]
    assert "185.10.20.30" in iocs["ips"]
    assert "http://evil.test/x.php" in iocs["urls"]

def test_parse_binary(tmp_path):
    #Given
    fichier = tmp_path / "pas_un_binaire.txt"
    fichier.write_bytes(b"text, unknow binary")
    sample = Sample(str(fichier))

    #When
    result = sample.parse_binary()

    #Then
    assert result == {"imports": [], "sections": []}


def test_shannon_entropy(tmp_path):
    #Given
    fichier = tmp_path / "repete.bin"
    fichier.write_bytes(b"aaaaaaaaaa")
    sample = Sample(str(fichier))

    #When
    entropy = sample.shannon_entropy()

    #Then
    assert entropy == 0.0

def extract_flag(self) -> str:
    """Retrouve le vrai flag dans les samples"""
    text = self.data.decode(errors="ignore")

    for m in re.finditer(r"ESGI\{[^}]*\}", text):
        avant = text[max(0, m.start() - 10):m.start()]
        if "FLAG=" in avant:
            return m.group()
    return ""