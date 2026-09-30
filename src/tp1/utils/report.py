class Report:
    def __init__(self, protocols: dict, filename: str):
        self.protocols = protocols
        self.filename = filename
        self.title = "Rapport d'analyse reseau - TP1"
        self.array = ""
        self.graph = ""

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
        Save report in a file
        """
        final_content = self.concat_report()
        with open(self.filename, "w") as report:
            report.write(final_content)

    def generate(self, param: str) -> None:
        """
        Generate graph and array
        """
        if param == "graph":
            graph = ""
            self.graph = graph
        elif param == "array":
            array = "Protocole      | Nombre de paquets\n"
            array += "---------------|------------------\n"
            for protocole, nombre in self.protocols.items():
                array += f"{protocole:<15}| {nombre}\n"
            self.array = array