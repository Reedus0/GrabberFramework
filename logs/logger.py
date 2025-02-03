import logging
import os

def init_logging(log_path):
    if not os.path.exists(log_path):
        os.makedirs(log_path, 0o777)

    logging.basicConfig(
        filename=log_path + "/log.txt", format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO
    )

    logging.getLogger(__name__)

    log("Initiated logger!")

def log(data):
    print("[INFO]", data)
    logging.info(data)