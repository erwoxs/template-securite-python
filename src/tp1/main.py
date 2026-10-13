import argparse
from tp1.utils.capture import Capture
from tp1.utils.config import logger
from tp1.utils.report import Report


def main():
    logger.info("Starting TP1")

    parser = argparse.ArgumentParser()
    parser.add_argument("--pcap", help="Fichier pcap a analyser")
    parser.add_argument("--out", help="Chemin du report.json a ecrire")
    args = parser.parse_args()

    capture = Capture()
    capture.capture_traffic(pcap=args.pcap)
    capture.analyse()

    report = Report(
        capture.protocols,
        "report.pdf",
        attacks=capture.attacks,
        flag=capture.flag or "",
    )
    report.generate("array")
    report.generate("graph")
    report.save("report.pdf")
    report.save_json(args.out)

    logger.info("Rapport genere")


if __name__ == "__main__":
    main()