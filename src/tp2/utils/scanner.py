import yara


class YaraScanner:
    def __init__(self, rules_path: str = "rules/rules.yar") -> None:
        self.rules_path = rules_path

    def scan(self, data: bytes) -> list[str]:
        """Noms des règles YARA déclenchées."""
        try:
            rules = yara.compile(self.rules_path)
            matches = rules.match(data=data)
            return [m.rule for m in matches]
        except yara.Error:
            return []
