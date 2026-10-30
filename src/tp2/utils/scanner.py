import yara
from pathlib import Path


class YaraScanner:
    def __init__(self, rules_path: str = "rules") -> None:
        self.rules_path = rules_path

    def scan(self, data: bytes) -> list[str]:
        """Noms des règles YARA déclenchées."""
        try:
            chemin = Path(self.rules_path)
            if chemin.is_dir():
                fichiers = {f.stem: str(f) for f in chemin.glob("*.yar")}
                rules = yara.compile(filepaths=fichiers)
            else:
                rules = yara.compile(str(chemin))
            matches = rules.match(data=data)
            return [m.rule for m in matches]
        except yara.Error:
            return []