import json
from fpdf import FPDF
class Report:
    def __init__(self, result: dict) -> None:
        self.result = result

    def generate_pdf(self, out_pdf: str) -> None:
        """Rapport PDF lisible (fpdf2)."""
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Helvetica", size=12)

        for cle, valeur in self.result.items():
            ligne = f"{cle} : {valeur}"
            pdf.cell(0, 8, ligne[:90], new_x="LMARGIN", new_y="NEXT")

        pdf.output(out_pdf)


    def generate_json(self, out_json: str) -> None:
        """Fichier JSON lisible."""
        with open(out_json, "w") as f:
            json.dump(self.result, f, indent=2)
