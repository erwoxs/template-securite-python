from tp1.utils.report import Report


def main():
    fake_protocols = {"TCP": 128, "ARP": 12, "DNS": 7, "ICMP": 4}

    report = Report(fake_protocols, "report.pdf")
    report.generate("array")
    print(report.array)


if __name__ == "__main__":
    main()