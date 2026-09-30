from tp1.utils.report import Report


def main():
    fake_protocols = {"TCP": 128, "ARP": 12, "DNS": 7, "ICMP": 4}

    report = Report(fake_protocols, "report.pdf")
    report.generate("array")
    report.generate("graph")
    report.save("report.pdf")
    print("Rapport PDF genere : report.pdf")


if __name__ == "__main__":
    main()