from tp1.utils.capture import Capture
from tp1.utils.report import Report


def main():
    # 1. La capture de ton binôme
    capture = Capture()
    capture.capture_traffic()
    protocols = capture.get_all_protocols()   # ses vraies données !

    # 2. Ton rapport, branché sur SES protocoles
    report = Report(protocols, "report.pdf")
    report.generate("array")
    report.generate("graph")
    report.save("report.pdf")
    report.save_json("report.json")
    print("Rapport PDF genere : report.pdf")
    print("Rapport JSON genere : report.json")


if __name__ == "__main__":
    main()