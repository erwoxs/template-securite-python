from unittest.mock import patch, mock_open, MagicMock
from tp1.utils.report import Report


def test_report_init():
    # Given
    protocols = {"TCP": 10, "ARP": 2}
    filename = "test.pdf"

    # When
    report = Report(protocols, filename)

    # Then
    #Initialise les attributs de l'objet Report
    assert report.protocols == protocols
    assert report.filename == filename
    assert report.title == "Rapport d'analyse reseau - TP1"
    assert report.array == ""
    assert report.graph == ""
    assert report.attacks == []
    assert report.flag == ""


def test_generate_array():
    # Given
    report = Report({"TCP": 10, "ARP": 2}, "test.pdf")

    # When
    report.generate("array")

    # Then
    assert "TCP" in report.array
    assert "10" in report.array
    assert "ARP" in report.array


def test_generate_graph():
    # Given
    report = Report({"TCP": 10}, "test.pdf")

    # When
    report.generate("graph")

    # Then
    assert "protocols.svg" in report.graph


def test_save_json():
    # Given
    protocols = {"TCP": 10}
    attacks = [{"type": "port_scan", "attacker": "10.0.0.1"}]
    flag = "ESGI{test}"
    report = Report(protocols, "test.pdf", attacks, flag)

    # When
    with patch("builtins.open", mock_open()) as mock_file:
        report.save_json("report.json")

        # Then
        mock_file.assert_called_once_with("report.json", "w")


def test_concat_report():
    # Given : Report avec des valeurs simples
    report = Report({}, "test.pdf")
    report.title = "Titre"
    report.array = "Tableau"
    report.graph = "Graphe"

    # When : Concatène
    result = report.concat_report()

    # Then : Résultat attendu de la concaténation
    assert result == "TitreTableauGraphe"

def test_save():
    # Given
    report = Report({"TCP": 10}, "test.pdf")
    report.array = "Protocole | Nombre\nTCP | 10"
    report.graph = "Graphique genere"

    # When : Remplace FPDF par un faux pour ne pas créer de vrai PDF
    with patch("tp1.utils.report.FPDF") as mock_fpdf:
        report.save("test.pdf")

        # Then : Vérifie qu'un PDF a été préparé et sauvegardé
        mock_fpdf.assert_called_once()
        mock_fpdf.return_value.output.assert_called_once_with("test.pdf")