import json
import pygal
from fpdf import FPDF

class Report:
    def __init__(self, protocols: dict, filename: str, attacks: list = None, flag: str = ""):
        self.protocols = protocols
        self.filename = filename
        self.title = "Rapport d'analyse reseau - TP1"
        self.array = ""
        self.graph = ""
        self.attacks = attacks or []
        self.flag = flag

    def concat_report(self) -> str:
        """
        Concat all data in report
        """
        content = ""
        content += self.title
        content += self.array
        content += self.graph

        return content

    def save(self, filename: str) -> None:
        """
        Save report in a PDF file
        """
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Helvetica", size=16)
        pdf.cell(0, 10, self.title, new_x="LMARGIN", new_y="NEXT")

        pdf.set_font("Helvetica", size=12)
        pdf.ln(5)
        for ligne in self.array.split("\n"):
            pdf.cell(0, 8, ligne, new_x="LMARGIN", new_y="NEXT")

        pdf.ln(5)
        pdf.cell(0, 8, self.graph, new_x="LMARGIN", new_y="NEXT")

        pdf.output(self.filename)

    def save_json(self, filename: str) -> None:
        """
        Save report data in a JSON file for auto-grading
        """
        data = {
            "protocols": self.protocols,
            "attacks": self.attacks,
            "flag": self.flag,
        }
        with open(filename, "w") as f:
            json.dump(data, f, indent=2)

    def generate(self, param: str) -> None:
        """
        Generate graph and array
        """
        if param == "graph":
            bar_chart = pygal.Bar()
            bar_chart.title = "Protocoles captures"
            for protocole, nombre in self.protocols.items():
                bar_chart.add(protocole, nombre)
            bar_chart.render_to_file("protocols.svg")
            self.graph = "Graphique genere : protocols.svg\n"
        elif param == "array":
            array = "Protocole      | Nombre de paquets\n"
            array += "---------------|------------------\n"
            for protocole, nombre in self.protocols.items():
                array += f"{protocole:<15}| {nombre}\n"
            self.array = array