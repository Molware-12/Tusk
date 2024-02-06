from tusk import Tusk
import logging

if __name__ == "__main__":
    tusk = Tusk("") # Input IP address here
    logging.basicConfig(filename="results.log", filemode="w", format='%(asctime)s %(message)s', level=logging.INFO)
    tusk.tusk_scan()
