import argparse #parse les arguments
from tp1.utils.capture import Capture
from tp1.utils.config import logger
from tp1.utils.report import Report


def main():
    logger.info("Starting TP1")

    parser = argparse.ArgumentParser()
    parser.add_argument("--pcap", help="Fichier pcap a analyser") #--pcap pour passer en args un pcap
    parser.add_argument("--out", help="Chemin du report.json a ecrire") #--out args pour fichier json
    args = parser.parse_args()
    args = parser.parse_args() #stocke le fichier comme argument
    capture = Capture()
    capture.capture_traffic(pcap=args.pcap) #args pcap à lire
    protocols = capture.get_all_protocols()

    report = Report(protocols, "report.pdf")
    report.generate("array")
    report.save_json("report.json")
    report.generate("graph")
    report.save("report.pdf")
    report.save_json(args.out) #sortie du json

    logger.info("Rapport PDF genere : report.pdf")
    logger.info("Rapport JSON genere : report.json")


if __name__ == "__main__":
    main()