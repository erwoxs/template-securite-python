from tp1.utils.report import Report


def main():
    fake_protocols = {"TCP": 128, "ARP": 12, "DNS": 7, "ICMP": 4}
    fake_attacks = [{"type": "port_scan", "attacker": "192.168.106.66"}]
    fake_flag = "ESGI{fake_pour_tester}"

    report = Report(fake_protocols, "report.pdf", fake_attacks, fake_flag)
    report.generate("array")
    report.generate("graph")
    report.save("report.pdf")
    report.save_json("report.json")
    print("Rapport PDF genere : report.pdf")
    print("Rapport JSON genere : report.json")


if __name__ == "__main__":
    main()