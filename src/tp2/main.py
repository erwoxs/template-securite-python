import argparse
from tp2.utils.report import Report
from tp2.utils.triage import Triage
from pathlib import Path


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--samples", required=True) #Ajoute un argument sample
    ap.add_argument("--rules", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--llm", choices=["openrouter", "ollama"], default="openrouter")
    args = ap.parse_args()

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True) #Crée un dossier si n'existe pas déjà

    for sample_path in Path(args.samples).iterdir():
        if not sample_path.is_file(): #Parcours chaque élément du dossier, s'il s'agit d'un fichier ounon
            continue

        triage = Triage(str(sample_path), args.llm)
        result = triage.run()

        report = Report(result)
        out_json = out_dir / f"{sample_path.name}.triage.json" #sort un rapport json
        out_pdf = out_dir / f"{sample_path.name}.triage.pdf"
        report.generate_json(str(out_json))
        report.generate_pdf(str(out_pdf))



if __name__ == "__main__":
    main()
