import argparse #parse les arguments
from tp1.utils.capture import Capture
from tp1.utils.config import logger
from tp1.utils.report import Report


def main():
    logger.info("Starting TP1")

    parser = argparse.ArgumentParser() #lit les arguments
    parser.add_argument("-f", "--file", help="Fichier pcap a analyser") #-f pour le fichier a scan
    args = parser.parse_args() #stocke le fichier comme argument
    capture = Capture()
    capture.capture_traffic(pcap=args.file)
    protocols = capture.get_all_protocols()

    report = Report(protocols, "report.pdf")
    report.generate("array")
    report.generate("graph")
    report.save("report.pdf")
    report.save_json("report.json")

    logger.info("Rapport PDF genere : report.pdf")
    logger.info("Rapport JSON genere : report.json")


if __name__ == "__main__":
    main()